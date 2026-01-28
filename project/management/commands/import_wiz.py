import base64
import json
import uuid
import requests
from datetime import datetime
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from django.conf import settings
from django.db import connection
from project.models import Project, Asset


class Command(BaseCommand):
    help = 'Import application endpoints from Wiz and create Asset objects'

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            required=True,
            help='Project ID (required)',
        )

    def pad_base64(self, data):
        """Makes sure base64 data is padded"""
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += "=" * (4 - missing_padding)
        return data

    def request_wiz_api_token(self, client_id, client_secret):
        """Retrieve an OAuth access token to be used against Wiz API"""
        headers_auth = {"Content-Type": "application/x-www-form-urlencoded"}
        auth_payload = {
            'grant_type': 'client_credentials',
            'audience': 'wiz-api',
            'client_id': client_id,
            'client_secret': client_secret
        }
        try:
            response = requests.post(
                url="https://auth.app.wiz.io/oauth/token",
                headers=headers_auth,
                data=auth_payload,
                timeout=180
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise CommandError(f"Error authenticating to Wiz (4xx/5xx): {str(e)}")
        except requests.exceptions.ConnectionError as e:
            raise CommandError(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
        except requests.exceptions.Timeout as e:
            raise CommandError(f"Request timed out: {str(e)}")

        try:
            response_json = response.json()
            token = response_json.get('access_token')
            if not token:
                message = f"Could not retrieve token from Wiz: {response_json.get('message')}"
                raise ValueError(message)
        except ValueError as exception:
            message = f"Could not parse API response {exception}. Check Service Account details and variables"
            raise ValueError(message) from exception

        response_json_decoded = json.loads(
            base64.standard_b64decode(self.pad_base64(token.split(".")[1]))
        )
        dc = response_json_decoded["dc"]
        return token, dc

    def query_wiz_api(self, query, variables, dc, token):
        """Query Wiz API for the given query data schema"""
        headers = {"Content-Type": "application/json"}
        headers["Authorization"] = f"Bearer {token}"
        data = {"variables": variables, "query": query}

        try:
            result = requests.post(
                url=f"https://api.{dc}.app.wiz.io/graphql",
                json=data,
                headers=headers,
                timeout=180
            )
            result.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise CommandError(f"Wiz-API-Error (4xx/5xx): {str(e)}")
        except requests.exceptions.ConnectionError as e:
            raise CommandError(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
        except requests.exceptions.Timeout as e:
            raise CommandError(f"Request timed out: {str(e)}")

        return result.json()

    def fetch_all_endpoints(self, dc, token):
        """Fetch all application endpoints from Wiz using pagination"""
        query = """
    query ApplicationEndpointsTable($first: Int, $after: String, $filterBy: ApplicationEndpointFilters, $orderBy: ApplicationEndpointOrder, $fetchTotalCount: Boolean = true) {
      applicationEndpoints(
        first: $first
        after: $after
        filterBy: $filterBy
        orderBy: $orderBy
      ) {
        nodes {
          id
          name
          host
          port
          protocols
          cloudPlatform
          cloudAccount {
            cloudProvider
            id
            externalId
          }
          firstSeen
          updatedAt
          portStatus
          httpResults {
            statusCode
            statusText
            pageTitle
            authenticationMethod
            authenticationServiceProvider
            contentType
            screenshotUrl
          }
          exposureLevel
          scanSources
          issueAnalytics {
            informationalSeverityCount
            lowSeverityCount
            mediumSeverityCount
            highSeverityCount
            criticalSeverityCount
            issueCount
          }
          hostedTechnologies {
            id
            technology {
              id
              name
              icon
            }
          }
          resources {
            providerUniqueId
            id
            name
            type
          }
        }
        pageInfo {
          endCursor
          hasNextPage
        }
        totalCount @include(if: $fetchTotalCount)
      }
    }
"""
        variables = {
            "fetchTotalCount": True,
            "first": 100,
            "filterBy": {},
            "orderBy": {
                "field": "RELATED_ISSUE_SEVERITY",
                "direction": "DESC"
            }
        }
        all_endpoints = []

        # Initial query
        result = self.query_wiz_api(query, variables, dc, token)

        # Check for errors
        if 'errors' in result:
            raise CommandError(f"GraphQL Error: {result['errors']}")

        # Get first page of results
        if 'data' in result and 'applicationEndpoints' in result['data']:
            endpoints_data = result['data']['applicationEndpoints']
            all_endpoints.extend(endpoints_data.get('nodes', []))

            total_count = endpoints_data.get('totalCount', 'unknown')
            self.stdout.write(f"[+] Total endpoints available: {total_count}")
            self.stdout.write(f"[+] Fetched {len(all_endpoints)} endpoints so far...")

            # Paginate through all remaining pages
            pageInfo = endpoints_data.get('pageInfo', {})
            page_num = 1

            while pageInfo.get('hasNextPage', False):
                page_num += 1
                # Fetch next page
                variables['after'] = pageInfo['endCursor']
                result = self.query_wiz_api(query, variables, dc, token)

                # if page_num > 2:
                #     break

                # Check for errors
                if 'errors' in result:
                    self.stdout.write(self.style.WARNING(f"Error on page {page_num}: {result['errors']}"))
                    break

                if 'data' in result and 'applicationEndpoints' in result['data']:
                    endpoints_data = result['data']['applicationEndpoints']
                    all_endpoints.extend(endpoints_data.get('nodes', []))
                    pageInfo = endpoints_data.get('pageInfo', {})
                    self.stdout.write(f"[+] Fetched page {page_num}: {len(all_endpoints)} total endpoints...")
                else:
                    break

        return all_endpoints

    def create_asset_from_endpoint(self, endpoint, project):
        """Create or update an Asset from a Wiz endpoint"""
        source_name = "wiz_application_endpoint"
        
        # Extract host from endpoint
        host = endpoint.get('host', '').strip()
        if not host:
            return None

        # Use host as the asset value
        asset_value = host.lower()

        # Generate UUID based on host and project
        # Convert to string since Asset.uuid is a CharField
        item_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{asset_value}:{project.id}"))

        # Build description from endpoint data
        description_parts = []
        if endpoint.get('resources'):
            resources = endpoint['resources']
            for resource in resources:
                if resource and resource.get('name'):
                    description_parts.append(f"Resource: {resource['name']}")
            # description_parts.append(f"Name: {endpoint['name']}")
        # if endpoint.get('name'):
        #     description_parts.append(f"Name: {endpoint['name']}")
        # if endpoint.get('port'):
        #     description_parts.append(f"Port: {endpoint['port']}")
        # if endpoint.get('protocols'):
        #     protocols = endpoint['protocols']
        #     if isinstance(protocols, list):
        #         protocols = ', '.join(protocols)
        #     description_parts.append(f"Protocols: {protocols}")
        # if endpoint.get('cloudPlatform'):
        #     description_parts.append(f"Cloud Platform: {endpoint['cloudPlatform']}")
        # if endpoint.get('portStatus'):
        #     description_parts.append(f"Port Status: {endpoint['portStatus']}")
        # if endpoint.get('exposureLevel'):
        #     description_parts.append(f"Exposure Level: {endpoint['exposureLevel']}")

        # # Add issue analytics if available
        # if endpoint.get('issueAnalytics'):
        #     analytics = endpoint['issueAnalytics']
        #     issue_counts = []
        #     if analytics.get('criticalSeverityCount', 0) > 0:
        #         issue_counts.append(f"Critical: {analytics['criticalSeverityCount']}")
        #     if analytics.get('highSeverityCount', 0) > 0:
        #         issue_counts.append(f"High: {analytics['highSeverityCount']}")
        #     if analytics.get('mediumSeverityCount', 0) > 0:
        #         issue_counts.append(f"Medium: {analytics['mediumSeverityCount']}")
        #     if issue_counts:
        #         description_parts.append(f"Issues ({', '.join(issue_counts)})")

        description = ", ".join(description_parts) if description_parts else ""

        # Determine asset type and subtype
        asset_type = 'domain'
        asset_subtype = 'subdomain'
        
        # Check if it's an IP address
        if '.' in asset_value and all(part.isdigit() for part in asset_value.split('.')):
            asset_type = 'ip'
            asset_subtype = 'ip'
        else:
            # Check if it's a domain/subdomain
            if '.' in asset_value:
                parts = asset_value.split('.')
                if len(parts) > 2:
                    asset_subtype = 'subdomain'
                else:
                    asset_subtype = 'domain'

        # Prepare asset data
        asset_data = {
            "related_project": project,
            "value": asset_value,
            "source": source_name,
            "type": asset_type,
            "subtype": asset_subtype,
            "scope": "external",
            "description": description,
            # "raw": endpoint,
            "monitor": True,
            "active": True,
            "creation_time": make_aware(datetime.now()),
            "last_seen_time": make_aware(datetime.now()),
        }

        # Set active status based on portStatus if available
        # port_status = endpoint.get('portStatus')
        # if port_status:
        #     asset_data["active"] = port_status.lower() in ['open', 'filtered']
        # else:
        #     asset_data["active"] = None

        # Create or update asset
        asset, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=asset_data)

        if not created:
            # Update existing asset
            # asset.raw = endpoint
            asset.last_seen_time = make_aware(datetime.now())
            asset.description = description
            asset.active = asset_data["active"]
            asset.monitor = asset_data["monitor"]

            # Update source if not already present
            source_parts = [s.strip() for s in asset.source.split(',')] if asset.source else []
            if source_name not in source_parts:
                source_parts.append(source_name)
                asset.source = ', '.join(source_parts)

            asset.save()

        return asset, created

    def handle(self, *args, **options):
        project_id = options['projectid']
        
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            raise CommandError(f"Project with ID {project_id} does not exist")
        
        projects = [project]

        total_asset_count = 0

        # Get Wiz API credentials from settings or use defaults
        client_id = getattr(settings, 'WIZ_CLIENT_ID', '')
        client_secret = getattr(settings, 'WIZ_CLIENT_SECRET', '')

        # Authenticate and get token
        self.stdout.write("[+] Authenticating with Wiz API...")
        try:
            token, dc = self.request_wiz_api_token(client_id, client_secret)
            self.stdout.write(f"[+] Successfully authenticated (DC: {dc})")
        except Exception as e:
            raise CommandError(f"Authentication failed: {str(e)}")

        # Fetch all endpoints
        self.stdout.write("[+] Fetching application endpoints from Wiz...")
        try:
            all_endpoints = self.fetch_all_endpoints(dc, token)
        except Exception as e:
            raise CommandError(f"Failed to fetch endpoints: {str(e)}")

        if not all_endpoints:
            self.stdout.write(self.style.WARNING("[!] No endpoints found in Wiz"))
            return

        self.stdout.write(f"[+] Found {len(all_endpoints)} endpoints in Wiz")

        # Process each project
        for project in projects:
            self.stdout.write(f"[+] Processing project: {project.projectname} (ID: {project.id})")
            self.stdout.write(f"[+] Processing {len(all_endpoints)} endpoints...")

            # Track imported asset UUIDs for this project (as strings)
            imported_uuids = set()
            created_count = 0
            updated_count = 0

            # Create/update assets from endpoints
            for endpoint in all_endpoints:
                result = self.create_asset_from_endpoint(endpoint, project)
                if result:
                    asset, created = result
                    # Ensure UUID is stored as string for consistent comparison
                    imported_uuids.add(str(asset.uuid))
                    if created:
                        created_count += 1
                    else:
                        updated_count += 1

            self.stdout.write(f"[+] Created {created_count} new assets")
            self.stdout.write(f"[+] Updated {updated_count} existing assets")

            # Ensure database connection sees the latest changes
            # This is important for SQLite which may cache queries within transactions
            # Close and reopen connection to ensure we see committed changes
            connection.close()
            
            # Delete assets that have only this source and are not in the current import
            source_name = "wiz_application_endpoint"
            self.stdout.write("[+] Cleaning up assets not in current import...")
            assets_to_check = Asset.objects.filter(
                related_project=project,
                source__contains=source_name
            )

            deleted_count = 0
            for asset in assets_to_check:
                # Skip if asset was just imported (compare as strings)
                asset_uuid_str = str(asset.uuid)
                if asset_uuid_str in imported_uuids:
                    continue

                # Check if asset has only this source
                source_parts = [s.strip() for s in asset.source.split(',')] if asset.source else []
                
                # If source is exactly this source or contains only this source
                if len(source_parts) == 1 and source_parts[0] == source_name:
                    # Remove this source (which will make it empty, so delete the asset)
                    asset.delete()
                    deleted_count += 1
                    self.stdout.write(f"[+] Deleted asset: {asset.value} (UUID: {asset.uuid}) because it had only this source")
                elif source_name in source_parts:
                    # Remove this source from the list
                    source_parts.remove(source_name)
                    new_source = ', '.join(source_parts).strip()
                    if not new_source:
                        # Source is empty, delete the asset
                        asset.delete()
                        deleted_count += 1
                        self.stdout.write(f"[+] Deleted asset: {asset.value} (UUID: {asset.uuid}) because it had only this source")
                    else:
                        # Update the source field
                        asset.source = new_source
                        asset.save()

            self.stdout.write(f"[+] Deleted {deleted_count} assets that were not in current import")
            self.stdout.write(self.style.SUCCESS(
                f"[+] Successfully imported {len(imported_uuids)} assets from Wiz for project {project.projectname} "
                f"(Created: {created_count}, Updated: {updated_count}, Deleted: {deleted_count})"
            ))
            total_asset_count += len(imported_uuids)

        self.stdout.write(self.style.SUCCESS(f"[+] Total assets processed across all projects: {total_asset_count}"))
