/**
 * Common DataTable utility functions
 * Used across multiple templates to reduce code duplication
 */

/**
 * Render a truncated cell with tooltip for long content
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
    
    // For sorting/filtering, return raw data
    if (type !== 'display') return data;
    
    options = options || {};
    var separator = options.separator || ', ';
    var maxItems = options.maxItems || 2;
    var maxLength = options.maxLength || null;
    var className = options.className || 'truncated-cell';
    
    var escapedData = $('<div/>').text(data).html();
    var needsTruncation = false;
    var preview = data;
    
    if (maxLength && data.length > maxLength) {
        // Truncate by character length
        preview = data.substring(0, maxLength) + '...';
        needsTruncation = true;
    } else if (separator && data.indexOf(separator) !== -1) {
        // Truncate by number of items
        var items = data.split(separator);
        if (items.length > maxItems) {
            preview = items.slice(0, maxItems).join(separator) + '... (+' + (items.length - maxItems) + ')';
            needsTruncation = true;
        }
    }
    
    var escapedPreview = $('<div/>').text(preview).html();
    
    if (needsTruncation) {
        return '<div class="' + className + '" rel="tooltip" data-placement="left" title="' + escapedData + '">' + escapedPreview + '</div>';
    }
    return '<div class="' + className + '" title="' + escapedData + '">' + escapedPreview + '</div>';
}

/**
 * Initialize tooltips for truncated cells after DataTable draw
 * Call this in fnCreatedCell or drawCallback
 */
function initTruncatedCellTooltips(nTd) {
    $('[rel="tooltip"]', nTd).tooltip();
}

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

// Common bulk toggle ignore status (using form submission)
function setupBulkToggleIgnore(table) {
    $('#toggle-ignore-selected-findings').on('click', function(e) {
        // Don't prevent default - let the form submit normally
        // The form will handle the bulk operation via POST
        var checked = $('#table_list_findings input[type="checkbox"][name="id[]"]:checked');
        if (checked.length === 0) {
            e.preventDefault();
            displayMessage('warning', 'No findings selected.');
            return;
        }
        // Form submission will be handled by the browser
        // The page will redirect and show a success message
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

// Common form submission handling for checkboxes
function setupFormSubmission(table) {
    $('#form-selected-findings').on('submit', function(e){
        var form = this;
        table.$('input[type="checkbox"]').each(function(){
            if(!$.contains(document, this)){
                if(this.checked){
                    $(form).append(
                        $('<input>')
                        .attr('type', 'hidden')
                        .attr('name', this.name)
                        .val(this.value)
                    );
                }
            } 
        });
    });
}

// Common edit comment modal functionality
function setupEditCommentModal(table, projectId) {
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
        
        // Send AJAX request to update comment
        $.ajax({
            url: "/api/v1/project/" + projectId + "/findings/" + findingId + "/update_comment/",
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

// Standalone Select All functionality (for non-DataTable usage)
function setupStandaloneSelectAll(selectAllSelector, tableSelector) {
    $(document).on('click', selectAllSelector, function() {
        var table = $(tableSelector).DataTable();
        var rows = table.rows({ 'search': 'applied' }).nodes();
        $('input[type="checkbox"]', rows).prop('checked', this.checked);
        
        // Update the select all checkbox state
        updateSelectAllState(selectAllSelector, tableSelector);
    });

    $(document).on('change', tableSelector + ' tbody input[type="checkbox"]', function() {
        updateSelectAllState(selectAllSelector, tableSelector);
    });
}

// Helper function to update select all checkbox state
function updateSelectAllState(selectAllSelector, tableSelector) {
    var table = $(tableSelector).DataTable();
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
    setupFormSubmission(table);
    
    // Optional features
    if (options.enableBulkIgnore) {
        setupBulkToggleIgnore(table);
    }
    
    if (options.hasNucleus) {
        setupSendToNucleus();
    }
    
    if (options.hasCommentModal && options.projectId) {
        setupEditCommentModal(table, options.projectId);
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
