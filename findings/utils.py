from findings.models import Finding
import requests
import json
import html


def asset_finding_get_or_create(asset_name, asset_id, vuln_obj, url, nucleus_project, request_header):

    # Finding details
    finding_severity = vuln_obj.severity.capitalize()
    if finding_severity == 'Info':
        finding_severity = 'Informational'
    finding_name = vuln_obj.name

    # Check if the finding exist
    data_body = {
        "asset_id": asset_id,
        "finding_name": finding_name,
        "finding_severity": finding_severity,
    }
    rsp = requests.post(f'{url}/projects/{nucleus_project}/findings/search', headers=request_header, json=data_body, verify=True)
    result_list = rsp.json()
    if len(result_list)>0:
        entry = result_list[0]
        entry_name = entry['asset_name']
        entry_id = entry['asset_id']
        print("Finding already exist")
        return entry_name, entry_id
    
    # If not -> create the finding
    new_finding = {
        "host_id": asset_id,

        "custom_finding_source": vuln_obj.source,
        "custom_finding_name": finding_name,
        "custom_finding_type": "Web Application",
        "finding_url": vuln_obj.url,

        "custom_finding_description": vuln_obj.description,
        "custom_finding_recommendation": vuln_obj.solution,
        "custom_finding_reference": vuln_obj.reference,

        "custom_finding_severity": finding_severity,
        "custom_finding_cve": vuln_obj.cve,
        "custom_finding_cvss": vuln_obj.cvssmetrics,
        "finding_additional_information": vuln_obj.vulnerabilityDetails,
        # "finding_code_snippet": vuln_obj.curl,
    }

    rsp = requests.post(f'{url}/projects/{nucleus_project}/findings', headers=request_header, json=new_finding, verify=True)
    # print(json.dumps(rsp.json(), indent=4))
    return True, "Entry Created"

def asset_get_or_create(asset_name, url, nucleus_project, request_header):
    entry_name = None
    entry_id = None
    request_parameter = {
        "asset_name": asset_name,
    }
    rsp = requests.get(f'{url}/projects/{nucleus_project}/assets', headers=request_header, params=request_parameter, verify=False)
    result_list = rsp.json()
    if len(result_list)>0:
        entry = result_list[0]
        entry_name = entry['asset_name']
        entry_id = entry['asset_id']
        return entry_name, entry_id
    else:
        request_parameter = {
            "asset_name": asset_name,
            "asset_type": "Application",
            "asset_notes": "Created with Shepherd automation",
            "asset_groups": ["Shepherd"],
            "asset_criticality": "High",
            "asset_public": True,
        }
        rsp = requests.post(f'{url}/projects/{nucleus_project}/assets', headers=request_header, json=request_parameter, verify=False)
        response = rsp.json()
        if response['success'] is True:
            entry_name = asset_name
            entry_id = response['asset_id']
        else:
            print('ERROR')
            print(json.dumps(rsp.json(), indent=4))
            return None, None
    return entry_name, entry_id

def ignore_finding(findingid):
    """move finding to ignore list
    """
    finding = Finding.objects.get(id=findingid)
    finding.ignore = not finding.ignore
    finding.save()

    return
