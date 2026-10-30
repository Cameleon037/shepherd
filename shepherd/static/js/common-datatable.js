/**
 * Common DataTable utility functions
 * Used across multiple templates to reduce code duplication
 */

// One presentation configuration for all DataTables (including dynamic tables).
$.extend(true, $.fn.dataTable.defaults, {
    processing: true,
    pageLength: 25,
    orderCellsTop: true,
    dom: '<"table-controls"l<"table-loading-slot"r>f<"table-columns-slot">><"table-scroll"t><"table-footer"ip>',
    language: {
        search: 'Search table: _INPUT_',
        searchPlaceholder: 'Search… (! excludes, comma adds terms)',
        processing: '<span class="table-loading-status" role="status"><span class="table-loading-spinner" aria-hidden="true"></span> Loading…</span>'
    },
    columnDefs: [{
        targets: '_all',
        render: function(data, type, row, meta) {
            var field = meta.settings.aoColumns[meta.col].mData;
            var detailFields = ['description', 'comment', 'banner', 'technologies', 'owner', 'vulnerabilityDetails'];
            if (detailFields.indexOf(field) !== -1 && typeof data === 'string' && data) {
                return renderTruncatedCell(data, type, { maxLength: 60 });
            }
            return data;
        }
    }]
});

function createServerSideTable(selector, url, columns, options) {
    return $(selector).DataTable($.extend(true, {
        serverSide: true,
        ajax: { url: url, dataSrc: 'results', type: 'GET', dataType: 'json' },
        columns: columns
    }, options || {}));
}

// Shared search lifecycle for DataTables and the project-wide endpoint search.
function setupSearchControl($input, $clear, search) {
    var timer;
    var help = 'Case-insensitive search. Separate terms with commas; all terms must match. Prefix ! to exclude.';
    $input.attr('title', help);
    function sync() { $clear.prop('disabled', !$input.val()); }
    function apply() {
        clearTimeout(timer);
        search($input.val().trim());
        sync();
    }
    function clear() {
        $input.val('');
        apply();
        $input.trigger('focus');
    }
    $input.off('.DT').on('input.tableSearch search.tableSearch', function() {
        clearTimeout(timer);
        sync();
        timer = setTimeout(apply, 400);
    }).on('keydown.tableSearch', function(e) {
        if (e.key === 'Enter' || e.key === 'Escape') {
            e.preventDefault();
            if (e.key === 'Escape') clear(); else apply();
        }
    });
    $clear.on('click.tableSearch', clear);
    sync();
    return function() {
        clearTimeout(timer);
        $input.add($clear).off('.tableSearch');
    };
}

function setupTableGlobalSearch(table) {
    var $filter = $(table.table().container()).find('.dataTables_filter');
    var $input = $filter.find('input').addClass('form-control input-sm');
    if (!$input.length) return;
    var $clear = $('<button>', {
        type: 'button', class: 'btn btn-link btn-sm table-search-clear',
        text: 'Clear', 'aria-label': 'Clear table search'
    }).appendTo($filter);
    var cleanup = setupSearchControl($input, $clear, function(value) {
        if (table.search() !== value) table.search(value, false, false).draw();
    });
    table.on('destroy.dt', cleanup);
}

/** Group the current page; the API orders matching rows together before paging. */
function setupTableGrouping(table) {
    var $table = $(table.table().node());
    var fields = ($table.attr('data-group-columns') || '').split(',');
    if (!fields[0]) return;
    var $control = $('<div>', { class: 'table-group-control' });
    var selectId = $table.attr('id') + '-group-by';
    $('<label>', { for: selectId, text: 'Group by:' }).appendTo($control);
    var $select = $('<select>', { id: selectId, class: 'form-control input-sm' }).appendTo($control);
    $('<option>', { value: '', text: 'None' }).appendTo($select);
    table.columns().every(function() {
        if (fields.indexOf(this.dataSrc()) !== -1) {
            $('<option>', { value: this.dataSrc(), text: $(this.header()).text().trim() }).appendTo($select);
        }
    });
    $control.insertBefore($(table.table().container()).find('.table-columns-slot'));

    table.on('preXhr.dt.tableGrouping', function(e, settings, data) {
        if ($select.val()) data.group_by = $select.val();
    });
    $select.on('change', function() { table.draw(); });

    function renderGroups() {
        $table.find('tbody .table-group-row').remove();
        var field = $select.val();
        if (!field) return;
        var groups = [];
        table.rows({ page: 'current' }).every(function() {
            var value = this.data()[field];
            var key = JSON.stringify(value == null || value === '' ? null : value);
            var group = groups[groups.length - 1];
            if (!group || group.key !== key) {
                group = { key: key, value: value, node: this.node(), count: 0 };
                groups.push(group);
            }
            group.count++;
        });
        var label = $select.find('option:selected').text();
        groups.forEach(function(group) {
            var value = group.value == null || group.value === '' ? '(No value)' : String(group.value);
            $('<tr>', { class: 'table-group-row' }).append(
                $('<td>', { colspan: table.columns(':visible').count() })
                    .append($('<strong>').text(label + ': ' + value))
                    .append($('<span>', { class: 'text-muted', text: ' (' + group.count + ' on this page)' }))
            ).insertBefore(group.node);
        });
    }
    table.on('draw.dt.tableGrouping', renderGroups);
    table.on('column-visibility.dt.tableGrouping', function() {
        $table.find('tbody .table-group-row td').attr('colspan', table.columns(':visible').count());
    });
    table.on('destroy.dt.tableGrouping', function() {
        $table.find('tbody .table-group-row').remove();
        $select.off('change');
        table.off('.tableGrouping');
    });
}

// One tooltip for all asset-detail links, including static and grouped tables.
function setupAssetDetailsLinks($tables) {
    var template = $('body').attr('data-asset-details-url');
    if (!template) return;
    var parts = template.split('__UUID__');
    $tables.find('a[href]').each(function() {
        if (this.origin !== window.location.origin) return;
        var path = this.pathname;
        if (!path.startsWith(parts[0]) || !path.endsWith(parts[1])) return;
        var assetId = path.slice(parts[0].length, path.length - parts[1].length);
        if (!assetId || assetId.indexOf('/') !== -1) return;
        $(this).removeAttr('title').attr('data-original-title', 'Show details')
            .tooltip({ container: 'body', placement: 'left', title: 'Show details' });
    });
}

$(function() {
    setupAssetDetailsLinks($('table'));

    // A body-level preview avoids clipping inside horizontally scrolling tables.
    var $preview = $('<img>', {
        class: 'screenshot-hover-preview', alt: '', 'aria-hidden': 'true'
    }).hide().appendTo('body');
    var screenshots = '.screenshot-preview a, #table_list_httpx_results tbody a:has(img)';
    $(document).on('mouseenter focusin', screenshots, function() {
        var $image = $(this).find('img');
        if ($image.length) $preview.attr('src', $image.attr('src')).show();
    }).on('mouseleave focusout', screenshots, function() {
        $preview.hide();
    }).on('keydown', function(e) {
        if (e.key === 'Escape') $preview.hide();
    });
    $(window).on('scroll resize', function() { $preview.hide(); });
    $(document).on('draw.dt', function() { $preview.hide(); });
});

// Bind original header cells, including ones detached by column visibility.
function applyDebouncedColumnSearch(table, inputSelector, selectSelector, delay) {
    inputSelector = inputSelector || 'input.column-search-input';
    selectSelector = selectSelector || 'select.column-search-input';
    delay = delay === undefined ? 400 : delay;
    var timers = {};
    var $headers = $();
    table.settings()[0].aoHeader.forEach(function(row) {
        row.forEach(function(header, index) {
            $(header.cell).attr('data-column', index);
            $headers = $headers.add(header.cell);
        });
    });
    var $inputs = $headers.find(inputSelector);
    var $selects = $headers.find(selectSelector);
    function columnIndex(input) {
        return Number($(input).closest('th').attr('data-column'));
    }
    $inputs.off('.tableColumnSearch').on('input.tableColumnSearch', function() {
        var index = columnIndex(this);
        var input = this;
        clearTimeout(timers[index]);
        timers[index] = setTimeout(function() {
            if (table.column(index).visible()) table.column(index).search(input.value).draw();
        }, delay);
    });
    $selects.off('.tableColumnSearch').on('change.tableColumnSearch', function() {
        table.column(columnIndex(this)).search(this.value).draw();
    });
    table.on('column-visibility.dt', function(e, settings, index, visible) {
        if (!visible) {
            clearTimeout(timers[index]);
            $headers.filter('[data-column="' + index + '"]').find(inputSelector + ', ' + selectSelector).val('');
        }
    });
    table.on('destroy.dt', function() {
        Object.keys(timers).forEach(function(index) { clearTimeout(timers[index]); });
        $inputs.add($selects).off('.tableColumnSearch');
    });
}

$(document).on('preInit.dt', function(e, settings) {
    $(settings.nTableWrapper).addClass('list-table');
    // DataTables has already detached initially hidden header cells here.
    settings.aoHeader.forEach(function(row) {
        row.forEach(function(header, index) { $(header.cell).attr('data-column', index); });
    });
}).on('init.dt', function(e, settings) {
    var table = new $.fn.dataTable.Api(settings);
    var lockedColumns = [];
    table.columns().every(function(index) {
        var $header = $(this.header());
        if ($header.find('input[type="checkbox"]').length || /^(actions|operations)$/i.test($header.text().trim())) {
            lockedColumns.push(index);
        }
    });
    setupTableColumnChooser(table, { lockedColumns: lockedColumns });
    setupTableGlobalSearch(table);
    setupTableGrouping(table);
    setupTableSelectionBar(table);
}).on('draw.dt', function(e, settings) {
    setupAssetDetailsLinks($(settings.nTable));
    // Keep icon-only row actions readable and keyboard-accessible.
    $(settings.nTable).find('tbody .btn').each(function() {
        var $button = $(this);
        var title = $button.attr('data-original-title') || $button.attr('title');
        if (title && !$button.attr('aria-label')) $button.attr('aria-label', title);
        if (!$button.hasClass('btn-primary') && !$button.hasClass('btn-danger') && !$button.hasClass('btn-success')) {
            $button.addClass('btn-default');
        }
        if ($button.find('.glyphicon-trash').length) $button.removeClass('btn-default').addClass('btn-danger');
    });
}).on('shown.bs.tab', '[data-toggle="tab"]', function() {
    $.fn.dataTable.tables({ visible: true, api: true }).columns.adjust();
});

/**
 * Render a fixed-width preview that opens full content in a shared dialog
 * @param {string} data - The data to render
 * @param {string} type - DataTables render type ('display', 'sort', 'filter', etc.)
 * @param {object} options - Configuration options
 * @param {string} options.separator - Separator for splitting items (default: ', ')
 * @param {number} options.maxItems - Max items to show before truncating (default: 2)
 * @param {number} options.maxLength - Max character length before truncating (alternative to maxItems)
 * @param {string} options.className - CSS class for the cell wrapper (default: 'truncated-cell')
 * @returns {string} - Rendered HTML or raw data for sorting/filtering
 * 
 * Usage in DataTable column definition:
 * { 
 *   data: 'ip', 
 *   render: function(data, type, row) {
 *     return renderTruncatedCell(data, type, { separator: ', ', maxItems: 2 });
 *   }
 * }
 */
function renderTruncatedCell(data, type, options) {
    if (!data) return '';
    if (type !== 'display') return data;
    
    options = options || {};
    var separator = options.separator;
    var maxItems = options.maxItems || 2;
    var maxLength = options.maxLength;
    var className = options.className || 'truncated-cell';
    
    var preview = data;
    if (maxLength && data.length > maxLength) {
        preview = data.substring(0, maxLength) + '…';
    } else if (separator && data.indexOf(separator) !== -1) {
        var items = data.split(separator);
        if (items.length > maxItems) {
            preview = items.slice(0, maxItems).join(separator) + '… (+' + (items.length - maxItems) + ')';
        }
    }
    return renderCellDetailsPreview(preview, data, className);
}

function renderCellDetailsPreview(preview, fullText, className, title) {
    return $('<button>', {
        type: 'button', class: 'table-cell-details ' + (className || ''),
        text: preview, 'data-full': fullText, 'data-detail-title': title || '',
        'aria-label': 'View full ' + (title || 'cell details'),
        'aria-haspopup': 'dialog', 'aria-controls': 'table-cell-details-modal'
    })[0].outerHTML;
}

$(function() {
    var $modal = $('#table-cell-details-modal');
    var $content = $('#table-cell-details-content');
    var $status = $('#table-cell-copy-status');
    var $copy = $('#copy-table-cell-details');
    var $trigger;

    $(document).on('click', '.table-cell-details', function() {
        $trigger = $(this);
        var columnTitle = $trigger.closest('table').find('thead tr:first th')
            .eq($trigger.closest('td').index()).text().trim();
        $('#table-cell-details-title').text($trigger.attr('data-detail-title') || columnTitle || 'Cell details');
        $content.text($trigger.attr('data-full'));
        $status.text('');
        $modal.modal('show');
    });

    $copy.on('click', async function() {
        $copy.prop('disabled', true);
        try {
            if (!navigator.clipboard) throw new Error('Clipboard unavailable');
            await navigator.clipboard.writeText($content.text());
            $status.text('Copied');
        } catch (e) {
            // Allow manual copying when clipboard access is blocked.
            var range = document.createRange();
            range.selectNodeContents($content[0]);
            var selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            $status.text('Text selected. Press Ctrl+C or ⌘C to copy.');
        } finally {
            $copy.prop('disabled', false);
        }
    });

    $modal.on('hidden.bs.modal', function() {
        if ($trigger && $trigger.is(':visible')) $trigger.trigger('focus');
    });
});

/**
 * Render comma-separated tag string as purple label badges (asset/suggestion Tag column).
 * Use in DataTable column: render: function(data, type, row) { return renderTagBadges(data, type); }
 */
function renderTagBadges(data, type) {
    if (!data || type !== 'display') return data || '';
    var tags = (typeof data === 'string' ? data.split(',') : []).map(function(tag) {
        return tag.trim();
    }).filter(function(tag) {
        return tag.length > 0;
    });
    return tags.map(function(tag) {
        return '<span class="label label-purple" style="margin-right: 4px;">' + $('<div/>').text(tag).html() + '</span>';
    }).join('');
}
if (typeof window !== 'undefined') { window.renderTagBadges = renderTagBadges; }

// Helper function to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== "") {
        const cookies = document.cookie.split(";");
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === name + "=") {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Helper function to display messages dynamically
function displayMessage(type, message) {
    var alertDiv = $('<div>')
        .addClass('alert alert-' + type)
        .text(message);

    // Append the message to the top of the page or a specific container
    $('.page-header').after(alertDiv);

    // Automatically remove the message after 5 seconds
    setTimeout(function () {
        alertDiv.fadeOut(function () {
            $(this).remove();
        });
    }, 5000);
}

// Common AJAX toggle ignore status (single row)
function setupToggleIgnoreFinding(table) {
    $(document).on("click", ".toggle-ignore-finding", function(e) {
        e.preventDefault();
        var url = $(this).attr('href');
        $.ajax({
            url: url,
            type: 'POST',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            },
            success: function(response) {
                if (response.success) {
                    displayMessage('info', response.message || 'Ignore status toggled.');
                    table.ajax.reload();
                } else {
                    displayMessage('danger', response.error || 'Toggle failed');
                }
            },
            error: function(xhr) {
                var errorMsg = 'Toggle failed';
                try {
                    var response = JSON.parse(xhr.responseText);
                    errorMsg = response.error || errorMsg;
                } catch (e) {
                    // Use default message if JSON parsing fails
                }
                displayMessage('danger', errorMsg);
            }
        });
    });
}

/**
 * Gather selected IDs from form and/or DataTables.
 * @param {object} config - formSelector, checkboxName, tableInstances (optional array of DataTable API instances)
 * @returns {string[]} - array of selected id/uuid values
 */
function getSelectedIdsFromBulkConfig(config) {
    var checkboxName = config.checkboxName || 'id[]';
    var ids = [];
    var seen = {};
    if (config.formSelector) {
        $(config.formSelector + ' input[type="checkbox"][name="' + checkboxName + '"]:checked').each(function() {
            var v = $(this).val();
            if (v && !seen[v]) { seen[v] = true; ids.push(v); }
        });
    }
    if (config.tableInstances && config.tableInstances.length) {
        config.tableInstances.forEach(function(table) {
            if (table && table.$) {
                table.$('input[type="checkbox"][name="' + checkboxName + '"]:checked').each(function() {
                    var v = $(this).val();
                    if (v && !seen[v]) { seen[v] = true; ids.push(v); }
                });
            }
        });
    }
    return ids;
}

/** Optional column chooser with browser-local preferences for each table. */
function setupTableColumnChooser(table, config) {
    config = config || {};
    var lockedColumns = config.lockedColumns || [];
    var tableId = table.table().node().id;
    var defaultColumns = $(table.table().node()).attr('data-default-columns');
    defaultColumns = defaultColumns ? defaultColumns.split(',') : null;
    var storageKey = 'shepherd.table-columns.' + window.location.pathname + '.' + tableId;
    var preferences = {};
    try {
        var saved = JSON.parse(localStorage.getItem(storageKey));
        if (saved && typeof saved === 'object' && !Array.isArray(saved)) preferences = saved;
    } catch (e) { /* Storage may be unavailable; the chooser still works. */ }

    var $chooser = $('<div>', { class: 'dropdown table-column-chooser' });
    var $button = $('<button>', {
        type: 'button', class: 'btn btn-default btn-sm dropdown-toggle',
        id: tableId + '-columns-button', 'data-toggle': 'dropdown',
        'aria-haspopup': 'true', 'aria-expanded': 'false',
        'aria-controls': tableId + '-columns-menu'
    }).appendTo($chooser);
    var $menu = $('<ul>', {
        class: 'dropdown-menu dropdown-menu-right', id: tableId + '-columns-menu',
        'aria-labelledby': tableId + '-columns-button'
    }).appendTo($chooser);

    table.columns().every(function(index) {
        var column = this;
        var locked = lockedColumns.indexOf(index) !== -1;
        var key = String(column.dataSrc()) + ':' + $(column.header()).text().trim();
        if (locked) column.visible(true, false);
        else if (typeof preferences[key] === 'boolean') column.visible(preferences[key], false);
        else if (defaultColumns) column.visible(defaultColumns.indexOf(column.dataSrc()) !== -1, false);

        var label = $(column.header()).text().trim();
        var $label = $('<label>', { class: 'table-column-option' }).appendTo($('<li>').appendTo($menu));
        $('<input>', {
            type: 'checkbox', checked: column.visible(), disabled: locked,
            'data-column-index': index
        }).appendTo($label).on('change', function() {
            var filtered = !this.checked && Boolean(column.search());
            if (filtered) {
                column.search('');
                $(table.table().node()).find('thead th[data-column="' + index + '"]')
                    .find('.column-search-input').val('');
            }
            column.visible(this.checked, false);
            table.columns.adjust();
            if (filtered) table.draw(false);
        });
        $('<span>').text(label + (locked ? ' (always visible)' : '')).appendTo($label);
    });

    $('<li>', { class: 'divider', role: 'separator' }).appendTo($menu);
    if (defaultColumns) {
        $('<button>', { type: 'button', class: 'btn btn-link btn-sm', text: 'Reset defaults' })
            .appendTo($('<li>', { class: 'table-column-reset' }).appendTo($menu))
            .on('click', function() {
                table.columns().every(function(index) {
                    var visible = lockedColumns.indexOf(index) !== -1 || defaultColumns.indexOf(this.dataSrc()) !== -1;
                    if (!visible && this.search()) {
                        this.search('');
                        $(table.table().node()).find('thead th[data-column="' + index + '"]')
                            .find('.column-search-input').val('');
                    }
                    this.visible(visible, false);
                });
                table.columns.adjust();
                table.draw(false);
            });
    }
    $('<button>', { type: 'button', class: 'btn btn-link btn-sm', text: 'Show all columns' })
        .appendTo($('<li>', { class: 'table-column-reset' }).appendTo($menu))
        .on('click', function() {
            table.columns().visible(true, false);
            table.columns.adjust();
        });
    $menu.on('click', function(e) { e.stopPropagation(); });
    $chooser.appendTo($(table.table().container()).find('.table-columns-slot'));

    function sync() {
        var state = {};
        table.columns().every(function(index) {
            state[String(this.dataSrc()) + ':' + $(this.header()).text().trim()] = this.visible();
            $menu.find('input[data-column-index="' + index + '"]').prop('checked', this.visible());
        });
        $button.text('Columns (' + table.columns(':visible').count() + '/' + table.columns().count() + ') ')
            .append($('<span>', { class: 'caret', 'aria-hidden': 'true' }));
        try { localStorage.setItem(storageKey, JSON.stringify(state)); } catch (e) {}
    }
    table.on('column-visibility.dt', sync);
    table.on('column-visibility.dt', function() {
        $(table.table().node()).find('.asset-group-row > td').attr('colspan', table.columns(':visible').count());
    });
    table.columns.adjust();
    sync();
}

/** Keep a table's bulk-action bar in sync with its rendered selection. */
function setupTableSelectionBar(table) {
    var $form = $(table.table().node()).closest('form');
    var $bar = $form.find('.list-selection-bar');
    if (!$bar.length) return;
    var tables = $form.data('selection-tables') || [];
    tables.push(table);
    table.on('destroy.dt', function() {
        var index = tables.indexOf(table);
        if (index !== -1) tables.splice(index, 1);
        var update = $form.data('selection-update');
        if (update) update();
    });
    $form.data('selection-tables', tables);
    if ($form.data('selection-bar-ready')) {
        table.on('draw.dt', $form.data('selection-update'));
        $form.data('selection-update')();
        return;
    }
    $form.data('selection-bar-ready', true);
    var checkboxSelector = 'input[type="checkbox"][name="id[]"]';

    function update() {
        var count = getSelectedIdsFromBulkConfig({
            tableInstances: tables
        }).length;
        $bar.find('[data-selection-count]').text(count + ' selected');
        $bar.find('[data-selection-action]').not('[data-selection-busy]').prop('disabled', count === 0);
        $bar.find('[data-clear-selection]').prop('disabled', count === 0);
        tables.forEach(function(api) {
            var $selectAll = $(api.table().node()).find('thead input[type="checkbox"]');
            var $checkboxes = api.$(checkboxSelector);
            var checked = $checkboxes.filter(':checked').length;
            $selectAll.prop('checked', checked > 0 && checked === $checkboxes.length)
                .prop('indeterminate', checked > 0 && checked < $checkboxes.length);
        });
    }

    // Select-all handlers run on document; update after they check the rows.
    $(document).on('change', '#' + $form.attr('id') + ' input[type="checkbox"]', update);
    table.on('draw.dt', update);
    $bar.find('[data-clear-selection]').on('click', function() {
        tables.forEach(function(api) { api.$(checkboxSelector).prop('checked', false); });
        update();
    });
    $form.data('selection-update', update);
    update();
}

/**
 * Setup bulk actions: intercept form/buttons, collect selected IDs, POST to API, reload tables.
 * @param {object} config - apiUrl, formSelector, checkboxName ('id[]' or 'uuid[]'), tableInstances (DataTable APIs to reload), buttons [{ name, action, confirm }]
 *   Example: { apiUrl: '{% url "api:bulk_assets" projectid=projectid %}', formSelector: '#form-selected', checkboxName: 'id[]', tableInstances: [assetsTable], buttons: [{ name: 'btnignore', action: 'ignore', confirm: false }, { name: 'btndelete', action: 'delete', confirm: true }] }
 */
function setupBulkActions(config) {
    if (!config || !config.apiUrl || !config.buttons || !config.buttons.length) return;
    var formSelector = config.formSelector || '#form-selected';
    var checkboxName = config.checkboxName || 'id[]';
    var tableInstances = config.tableInstances || [];
    var apiUrl = config.apiUrl;

    function doBulkAction(action, needConfirm, done) {
        var ids = getSelectedIdsFromBulkConfig({ formSelector: formSelector, checkboxName: checkboxName, tableInstances: tableInstances });
        if (!ids.length) {
            displayMessage('warning', 'No items selected.');
            if (done) done();
            return;
        }
        function sendRequest() {
            var formData = new FormData();
            formData.append('action', action);
            formData.append('csrfmiddlewaretoken', getCookie('csrftoken'));
            ids.forEach(function(id) { formData.append(checkboxName, id); });
            $.ajax({
                url: apiUrl,
                type: 'POST',
                headers: { 'X-CSRFToken': getCookie('csrftoken') },
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    if (response.success) {
                        displayMessage('info', response.message || 'Action completed.');
                        tableInstances.forEach(function(t) { if (t && t.ajax && t.ajax.reload) t.ajax.reload(); });
                        $(formSelector + ' input[type="checkbox"][name="select_all"], ' + formSelector + ' input[id^="select-all-"]').prop('checked', false).prop('indeterminate', false);
                    } else {
                        displayMessage('danger', response.error || 'Action failed.');
                    }
                    if (done) done();
                },
                error: function(xhr) {
                    var err = 'Action failed.';
                    try { var r = JSON.parse(xhr.responseText); if (r.error) err = r.error; } catch (e) {}
                    displayMessage('danger', err);
                    if (done) done();
                }
            });
        }
        if (needConfirm && typeof bootbox !== 'undefined') {
            bootbox.confirm('Are you sure?', function(confirmed) {
                if (confirmed) sendRequest(); else if (done) done();
            });
        } else {
            sendRequest();
        }
    }

    config.buttons.forEach(function(btn) {
        var name = btn.name || btn.id;
        var action = btn.action;
        var needConfirm = !!btn.confirm;
        if (!name || action === undefined) return;
        $(formSelector).on('click', '[name="' + name + '"], [id="' + name + '"]', function(e) {
            e.preventDefault();
            e.stopPropagation();
            doBulkAction(action, needConfirm);
        });
    });

    $(formSelector).on('submit', function(e) {
        e.preventDefault();
        return false;
    });
}

/**
 * Setup row-level action buttons (monitor/ignore/move/activate/delete) that POST to
 * a bulk API (or a direct view URL) and reload the tables without a page refresh.
 * @param {object} config - apiUrl (bulk API URL), tableInstances (DataTable APIs to reload),
 *   confirmActions (array of action names that require a bootbox confirm, e.g. ['delete'])
 * Row buttons must have class "row-action", data-action, data-uuid (or data-url for direct views),
 *   and optionally data-display (shown in the confirm dialog).
 */
function setupRowActions(config) {
    config = config || {};
    var apiUrl = config.apiUrl;
    var tableInstances = config.tableInstances || [];
    var confirmActions = config.confirmActions || [];

    $(document).on('click', '.row-action', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var action = $btn.attr('data-action');
        var uuid = $btn.attr('data-uuid');
        var url = $btn.attr('data-url');
        var display = $btn.attr('data-display');

        function sendRequest() {
            var formData = new FormData();
            formData.append('action', action);
            formData.append('csrfmiddlewaretoken', getCookie('csrftoken'));
            if (uuid) formData.append('id[]', uuid);
            $.ajax({
                url: url || apiUrl,
                type: 'POST',
                headers: {
                    'X-CSRFToken': getCookie('csrftoken'),
                    'X-Requested-With': 'XMLHttpRequest'
                },
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    if (response && response.success) {
                        displayMessage('info', response.message || 'Action completed.');
                        tableInstances.forEach(function (t) {
                            if (t && t.ajax && t.ajax.reload) t.ajax.reload();
                        });
                    } else {
                        displayMessage('danger', (response && response.error) || 'Action failed.');
                    }
                },
                error: function (xhr) {
                    var err = 'Action failed.';
                    try { var r = JSON.parse(xhr.responseText); if (r.error) err = r.error; } catch (e2) {}
                    displayMessage('danger', err);
                }
            });
        }

        if (confirmActions.indexOf(action) !== -1 && typeof bootbox !== 'undefined') {
            var msg = display ? ('Are you sure?<br/>(Entry: ' + display + ')') : 'Are you sure?';
            bootbox.confirm(msg, function (confirmed) {
                if (confirmed) sendRequest();
            });
        } else {
            sendRequest();
        }
    });
}

// Common bootbox confirm dialog
function setupConfirmDialog(table) {
    $(document).on("click", ".confirm", function(e) {
        e.preventDefault();
        var title = $(this).attr('data-display');
        var location = $(this).attr('data-href');
        var method = $(this).attr('data-method');
        var form = $(this).closest('form');
        var buttonName = $(this).attr('name');

        bootbox.confirm('Are you sure?', function(confirmed) {
            if (confirmed) {
                if (method && method.toUpperCase() === 'DELETE') {
                    // If data-method is DELETE, send DELETE request via AJAX
                    $.ajax({
                        url: location,
                        type: 'DELETE',
                        headers: {
                            'X-CSRFToken': getCookie('csrftoken')
                        },
                        success: function(response) {
                            displayMessage('info', 'Entry deleted successfully.');
                            table.ajax.reload();
                        },
                        error: function(xhr) {
                            var error = xhr.responseText ? JSON.parse(xhr.responseText) : {error: 'Delete failed'};
                            displayMessage('danger', 'Error: ' + (error.error || 'Delete failed'));
                        }
                    });
                } else if (form.length) {
                    $('<input>')
                        .attr('type', 'hidden')
                        .attr('name', 'action_url')
                        .val(location)
                        .appendTo(form);
                    if (buttonName) {
                        $('<input>')
                            .attr('type', 'hidden')
                            .attr('name', buttonName)
                            .val('true')
                            .appendTo(form);
                    }
                    form.submit();
                } else {
                    window.location.replace(location);
                }
            }
        });
    });
}

// Common "Send to Nucleus" functionality
function setupSendToNucleus() {
    $(document).on("click", ".send-to-nucleus", function (e) {
        e.preventDefault();
        displayMessage("info", "Sending the finding to Nucleus...");
    
        var url = $(this).data("url");
        var title = $(this).data("display");
    
        $.ajax({
            url: url,
            type: "POST",
            headers: {
                "X-CSRFToken": getCookie("csrftoken")
            },
            success: function (response) {
                displayMessage("info", "Finding sent to Nucleus successfully.");
            },
            error: function (xhr) {
                var error = JSON.parse(xhr.responseText);
                displayMessage("danger", "Error: " + error.error);
            }
        });
    });
}

// Common checkbox "Select all" functionality
function setupSelectAllCheckboxes(table, selectAllId, tableId) {
    selectAllId = selectAllId || '#select-all-findings';
    tableId = tableId || '#table_list_findings';
    
    // Handle click on "Select all" control
    $(selectAllId).on('click', function(){
        var rows = table.rows({ 'search': 'applied' }).nodes();
        $('input[type="checkbox"]', rows).prop('checked', this.checked);
        
        // Update the select all checkbox state
        updateSelectAllStateForTable(selectAllId, table);
    });
    
    // Handle click on checkbox to set state of "Select all" control
    $(tableId + ' tbody').on('change', 'input[type="checkbox"]', function(){
        updateSelectAllStateForTable(selectAllId, table);
    });
}

// Helper function to update select all checkbox state for DataTable
function updateSelectAllStateForTable(selectAllSelector, table) {
    var rows = table.rows({ 'search': 'applied' }).nodes();
    var checkboxes = $('input[type="checkbox"]', rows);
    var checkedCount = checkboxes.filter(':checked').length;
    var totalCount = checkboxes.length;
    
    var selectAllCheckbox = $(selectAllSelector).get(0);
    if (selectAllCheckbox) {
        if (checkedCount === 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        } else if (checkedCount === totalCount) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.indeterminate = false;
        } else {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = true;
        }
    }
}

// Common edit comment modal functionality.
// commentUrlTemplate must contain the literal placeholder __ID__ for the finding id
// (e.g. from {% url 'api:update_finding_comment' projectid=projectid findingid='__ID__' %}).
function setupEditCommentModal(table, commentUrlTemplate) {
    // Edit comment modal functionality
    $(document).on("click", ".edit-comment", function(e) {
        e.preventDefault();
        var findingId = $(this).data("id");
        
        // Get comment from the row data instead of DOM traversal
        var rowData = table.row($(this).closest("tr")).data();
        var currentComment = rowData ? rowData.comment || "" : "";
        
        // Store the finding ID for later use
        $('#editCommentModal').data('finding-id', findingId);
        
        // Populate modal with current comment
        $("#commentText").val(currentComment.trim());
        
        // Show modal
        $("#editCommentModal").modal("show");
    });

    // Save comment button handler
    $("#saveCommentButton").on("click", function() {
        var findingId = $('#editCommentModal').data('finding-id');
        var updatedComment = $("#commentText").val();
        var url = commentUrlTemplate.replace('__ID__', findingId);
        
        // Send AJAX request to update comment
        $.ajax({
            url: url,
            type: "POST",
            headers: {
                "X-CSRFToken": getCookie("csrftoken")
            },
            data: {
                comment: updatedComment
            },
            success: function(response) {
                // Hide modal
                $("#editCommentModal").modal("hide");
                
                // Reload the table to show updated comment
                table.ajax.reload();
                
                displayMessage("success", "Comment updated successfully.");
            },
            error: function(xhr) {
                displayMessage("danger", "Failed to update comment. Please try again.");
                console.log("Error updating comment:", xhr.responseText);
            }
        });
    });
}

// Select-all adapter for pages that initialize their tables separately.
function setupStandaloneSelectAll(selectAllSelector, tableSelector) {
    setupSelectAllCheckboxes($(tableSelector).DataTable(), selectAllSelector, tableSelector);
}

// Standalone Confirm Dialog (for simple redirects)
function setupStandaloneConfirm() {
    $(document).on("click", ".confirm", function(e) {
        e.preventDefault();
        var title = $(this).attr('data-display') || 'Are you sure?';
        var location = $(this).attr('data-href');
        var form = $(this).closest('form');
        var buttonName = $(this).attr('name');
        var buttonValue = $(this).val();

        bootbox.confirm(title, function(confirmed) {
            if (confirmed) {
                if (form.length && buttonName) {
                    // Form-based submission with button
                    $('<input>').attr({
                        type: 'hidden',
                        name: buttonName,
                        value: buttonValue || 'true'
                    }).appendTo(form);
                    form.submit();
                } else if (location) {
                    // Simple redirect
                    window.location.replace(location);
                }
            }
        });
    });
}

// Initialize all common DataTable functionality
function initializeCommonDataTableFeatures(table, options) {
    options = options || {};
    
    // Setup all common features
    setupToggleIgnoreFinding(table);
    setupConfirmDialog(table);
    setupSelectAllCheckboxes(table, options.selectAllId, options.tableId);
    
    if (options.hasNucleus) {
        setupSendToNucleus();
    }
    
    if (options.hasCommentModal && options.commentUrlTemplate) {
        setupEditCommentModal(table, options.commentUrlTemplate);
    }
}

// Initialize common functionality for non-DataTable pages
function initializeStandaloneFeatures(options) {
    options = options || {};
    
    // Setup standalone confirm dialogs
    setupStandaloneConfirm();
    
    // Setup select all if specified
    if (options.selectAllSelector && options.tableSelector) {
        setupStandaloneSelectAll(options.selectAllSelector, options.tableSelector);
    }
}

/**
 * Initialize upload modal with drag & drop functionality
 * @param {object} config - Configuration object
 * @param {string} config.modalId - Modal ID (e.g., '#UploadDomainsModal')
 * @param {string} config.dropZoneId - Drop zone ID (e.g., '#upload-drop-zone')
 * @param {string} config.fileInputId - File input ID (e.g., '#modal-domain-file')
 * @param {string} config.fileInfoId - File info container ID (e.g., '#upload-file-info')
 * @param {string} config.fileNameId - File name display ID (e.g., '#upload-file-name')
 * @param {string} config.submitBtnId - Submit button ID (e.g., '#upload-submit-btn')
 * @param {string} config.dropTextId - Drop zone text ID (e.g., '#upload-drop-text')
 * @param {string} config.clearBtnId - Clear file button ID (e.g., '#upload-clear-file')
 * @param {string} config.acceptedExtension - Accepted file extension (default: '.txt')
 */
function initializeUploadModal(config) {
    config = config || {};
    var modalId = config.modalId;
    var dropZoneId = config.dropZoneId;
    var fileInputId = config.fileInputId;
    var fileInfoId = config.fileInfoId;
    var fileNameId = config.fileNameId;
    var submitBtnId = config.submitBtnId;
    var dropTextId = config.dropTextId;
    var clearBtnId = config.clearBtnId;
    var acceptedExtension = config.acceptedExtension || '.txt';
    
    if (!modalId || !dropZoneId || !fileInputId || !fileInfoId || !fileNameId || !submitBtnId || !dropTextId || !clearBtnId) {
        console.error('initializeUploadModal: Missing required configuration');
        return;
    }
    
    var $dropZone = $(dropZoneId);
    var $fileInput = $(fileInputId);
    var $fileInfo = $(fileInfoId);
    var $fileName = $(fileNameId);
    var $submitBtn = $(submitBtnId);
    var $dropText = $(dropTextId);
    
    // Tag the drop zone so theme-aware CSS can style it (light & dark mode).
    $dropZone.addClass('upload-dropzone');
    
    function updateFileDisplay(file) {
        if (file) {
            $fileName.text(file.name);
            $fileInfo.addClass('upload-file-info').show();
            $dropZone.removeClass('is-hover').addClass('is-filled');
            $dropText.html('<span class="upload-dropzone-filled-text">File selected</span>');
            $submitBtn.prop('disabled', false);
        } else {
            $fileInfo.hide();
            $dropZone.removeClass('is-hover is-filled');
            $dropText.html('Drag &amp; drop a ' + acceptedExtension + ' file here<br><small>or click to browse</small>');
            $submitBtn.prop('disabled', true);
        }
    }
    
    // Click to browse. Use the native DOM click() so the browser opens the file
    // picker. jQuery's .click() shortcut only fires synthetic handlers and does
    // not invoke the native file dialog on <input type="file"> in jQuery 3+.
    $dropZone.on('click', function(e) {
        if (e.target === $fileInput[0]) {
            return;
        }
        if ($fileInput[0]) {
            $fileInput[0].click();
        }
    });
    
    $fileInput.on('change', function() {
        updateFileDisplay(this.files[0]);
    });
    
    // Drag and drop
    $dropZone.on('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('is-hover');
    });
    
    $dropZone.on('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).removeClass('is-hover');
    });
    
    $dropZone.on('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).removeClass('is-hover');
        var files = e.originalEvent.dataTransfer.files;
        if (files.length && files[0].name.endsWith(acceptedExtension)) {
            $fileInput[0].files = files;
            updateFileDisplay(files[0]);
        } else {
            bootbox.alert('Please upload a ' + acceptedExtension + ' file.');
        }
    });
    
    // Clear file
    $(clearBtnId).on('click', function(e) {
        e.stopPropagation();
        $fileInput.val('');
        updateFileDisplay(null);
    });
    
    // Reset on modal close
    $(modalId).on('hidden.bs.modal', function() {
        $fileInput.val('');
        updateFileDisplay(null);
    });
}

/**
 * Render an Asset.registrant_info dict as a compact key-value block.
 * Shows the first field as a fixed preview; click opens all fields.
 * Non-display types return raw JSON for sorting/filtering.
 *
 * Usage in DataTable column definition:
 *   render: function(data, type, row) { return renderRegistrantInfo(data, type); },
 */
function renderRegistrantInfo(data, type) {
    if (type && type !== 'display') return JSON.stringify(data || '');
    if (!data || typeof data !== 'object') return '';
    var fields = [
        ['Org',       data.registrant_org],
        ['Name',      data.registrant_name],
        ['Email',     data.registrant_email],
        ['Phone',     data.registrant_phone],
        ['City',      data.registrant_city],
        ['Country',   data.registrant_country],
        ['Registrar', data.registrar],
        ['Created',   data.registration_created],
        ['Expires',   data.registration_expires],
        ['Active',    data.active != null ? String(data.active) : null],
    ];
    var lines = fields.filter(function(f) { return f[1]; }).map(function(f) {
        return f[0] + ': ' + f[1];
    });
    if (!lines.length) return '';
    var preview = lines[0] + (lines.length > 1 ? ' (+' + (lines.length - 1) + ')' : '');
    return renderCellDetailsPreview(preview, lines.join('\n'), 'registrant-cell', 'Registrant information');
}
