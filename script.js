class JSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.reviewedItems = new Set();
        this.currentReport = null;
        
        console.log('🚀 JSONViewer constructor called');
        
        // Initialize everything in the correct order
        this.initEventListeners();
        
        // Load data after a short delay to ensure DOM is ready
        setTimeout(() => {
            this.loadReviewedItems();
            this.loadStoredData();
        }, 200);
    }

    // Custom popup methods
    showPopup(message, type = 'info', title = '', actions = null) {
        const popup = document.createElement('div');
        popup.className = `custom-popup ${type}`;
        
        const titleText = title || this.getDefaultTitle(type);
        
        popup.innerHTML = `
            <div class="popup-header">
                <div class="popup-title">${titleText}</div>
                <button class="popup-close">&times;</button>
            </div>
            <div class="popup-message">${message}</div>
            ${actions ? `<div class="popup-actions">${actions}</div>` : ''}
        `;
        
        document.body.appendChild(popup);
        
        // Show popup with animation
        setTimeout(() => popup.classList.add('show'), 10);
        
        // Auto-hide after 5 seconds if no actions
        if (!actions) {
            setTimeout(() => this.hidePopup(popup), 5000);
        }
        
        // Close button handler
        popup.querySelector('.popup-close').addEventListener('click', () => {
            this.hidePopup(popup);
        });
        
        return popup;
    }

    showConfirmPopup(message, onConfirm, onCancel = null, type = 'warning') {
        const actions = `
            <button class="popup-btn danger" data-action="confirm">Yes, Continue</button>
            <button class="popup-btn secondary" data-action="cancel">Cancel</button>
        `;
        
        const popup = this.showPopup(message, type, 'Confirm Action', actions);
        
        popup.querySelector('[data-action="confirm"]').addEventListener('click', () => {
            this.hidePopup(popup);
            if (onConfirm) onConfirm();
        });
        
        popup.querySelector('[data-action="cancel"]').addEventListener('click', () => {
            this.hidePopup(popup);
            if (onCancel) onCancel();
        });
    }

    showAppendConfirmPopup(existingCount, newCount, onAppend, onReplace) {
        const message = `You already have <strong>${existingCount}</strong> items loaded.<br><br>
            <strong>Choose your action:</strong><br>
            • <strong>Add to Top</strong> - Add the new ${newCount} items to the beginning<br>
            • <strong>Replace All</strong> - Replace existing data with new data`;
        
        const actions = `
            <button class="popup-btn primary" data-action="append">📎 Add to Top</button>
            <button class="popup-btn secondary" data-action="replace">🔄 Replace All</button>
            <button class="popup-btn secondary" data-action="cancel">❌ Cancel</button>
        `;
        
        const popup = this.showPopup(message, 'info', 'File Upload Options', actions);
        
        popup.querySelector('[data-action="append"]').addEventListener('click', () => {
            this.hidePopup(popup);
            if (onAppend) onAppend();
        });
        
        popup.querySelector('[data-action="replace"]').addEventListener('click', () => {
            this.hidePopup(popup);
            if (onReplace) onReplace();
        });
        
        popup.querySelector('[data-action="cancel"]').addEventListener('click', () => {
            this.hidePopup(popup);
        });
    }

    hidePopup(popup) {
        popup.classList.remove('show');
        setTimeout(() => {
            if (popup.parentNode) {
                popup.parentNode.removeChild(popup);
            }
        }, 300);
    }

    getDefaultTitle(type) {
        const titles = {
            success: '✅ Success',
            error: '❌ Error',
            warning: '⚠️ Warning',
            info: 'ℹ️ Information'
        };
        return titles[type] || 'Notification';
    }

    initEventListeners() {
        console.log('🎯 Initializing event listeners');
        
        const fileInput = document.getElementById('fileInput');
        const uploadArea = document.getElementById('uploadArea');
        const globalSearch = document.getElementById('globalSearch');
        const clearReviewed = document.getElementById('clearReviewed');
        const exportData = document.getElementById('exportData');

        // File upload handlers
        uploadArea?.addEventListener('click', () => fileInput.click());
        fileInput?.addEventListener('change', (e) => this.handleFileUpload(e));

        // Drag and drop
        uploadArea?.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea?.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea?.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.processFile(files[0]);
            }
        });

        // Search and controls
        globalSearch?.addEventListener('input', (e) => this.handleGlobalSearch(e.target.value));
        clearReviewed?.addEventListener('click', () => this.clearAllData());
        exportData?.addEventListener('click', () => this.exportData());

        // Modal event listeners
        this.initModalEventListeners();
    }

    initModalEventListeners() {
        const modal = document.getElementById('reportModal');
        const closeModal = document.getElementById('closeModal');
        const copyAllReport = document.getElementById('copyAllReport');
        const downloadReport = document.getElementById('downloadReport');

        closeModal?.addEventListener('click', () => {
            if (modal) modal.style.display = 'none';
        });

        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });

        copyAllReport?.addEventListener('click', () => this.copyAllReport());
        downloadReport?.addEventListener('click', () => this.downloadReport());

        // Individual copy buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-btn')) {
                const targetId = e.target.dataset.target;
                this.copyToClipboard(targetId, e.target);
            }
        });
    }

    handleFileUpload(event) {
        const file = event.target.files[0];
        if (file) {
            this.processFile(file);
        }
    }

    processFile(file) {
        if (!file.name.toLowerCase().endsWith('.json')) {
            this.showPopup('Please upload a JSON file', 'error');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const jsonData = JSON.parse(e.target.result);
                const newDataArray = Array.isArray(jsonData) ? jsonData : [jsonData];
                
                console.log('📁 Processing new file with', newDataArray.length, 'items');
                
                // Check if we have existing data
                if (this.data.length > 0) {
                    // Show custom append confirmation popup
                    this.showAppendConfirmPopup(
                        this.data.length,
                        newDataArray.length,
                        () => this.appendDataToTop(newDataArray),
                        () => {
                            this.loadDataIntoApp(newDataArray);
                            this.saveToLocalStorage(newDataArray);
                        }
                    );
                } else {
                    // No existing data, just load normally
                    this.loadDataIntoApp(newDataArray);
                    this.saveToLocalStorage(newDataArray);
                }
                
            } catch (error) {
                console.error('❌ JSON parsing error:', error);
                this.showPopup(`Invalid JSON file: ${error.message}`, 'error');
            }
        };
        reader.readAsText(file);
    }

    // New method to append data to the top
    appendDataToTop(newDataArray) {
        console.log('📎 Appending', newDataArray.length, 'new items to the top');
        
        // Get current raw data without the processed fields
        const existingRawData = this.getRawDataArray();
        
        // Combine new data at the top with existing data
        const combinedRawData = [...newDataArray, ...existingRawData];
        
        // Reload with combined data
        this.loadDataIntoApp(combinedRawData);
        this.saveToLocalStorage(combinedRawData);
        
        console.log('✅ Data appended successfully. Total items:', this.data.length);
        this.showPopup(
            `Added <strong>${newDataArray.length}</strong> new items to the top!<br>Total items: <strong>${this.data.length}</strong>`,
            'success'
        );
    }

    // New helper method to get raw data array (without processed fields)
    getRawDataArray() {
        return this.data.map(item => {
            // Remove processed fields and return original data
            const { id, reviewed, ...rawItem } = item;
            return rawItem;
        });
    }

    loadDataIntoApp(rawData) {
        console.log('📊 Loading data into app:', rawData.length, 'items');
        
        this.data = rawData.map((item, index) => ({
            ...item,
            id: index,
            reviewed: this.reviewedItems.has(this.generateItemId(item))
        }));
        
        this.filteredData = [...this.data];
        
        // Update UI
        this.updateSummary();
        this.renderTable();
        this.showDataUI();
        
        console.log('✅ Data loaded successfully');
    }

    saveToLocalStorage(rawDataArray) {
        try {
            const storageData = {
                data: rawDataArray,
                timestamp: new Date().toISOString(),
                version: '1.0'
            };
            
            localStorage.setItem('jsonViewerData', JSON.stringify(storageData));
            console.log('💾 Data saved to localStorage');
            
        } catch (error) {
            console.error('❌ Failed to save to localStorage:', error);
            
            if (error.name === 'QuotaExceededError') {
                this.showPopup('Storage space full! Clearing old data...', 'warning');
                this.clearAllData();
                // Try again after clearing
                try {
                    localStorage.setItem('jsonViewerData', JSON.stringify(storageData));
                    console.log('💾 Data saved after clearing old data');
                    this.showPopup('Data saved after clearing old data', 'success');
                } catch (retryError) {
                    this.showPopup('Unable to save data due to storage limitations.', 'error');
                }
            }
        }
    }

    loadStoredData() {
        console.log('🔍 Checking for stored data...');
        
        try {
            const storedData = localStorage.getItem('jsonViewerData');
            
            if (!storedData) {
                console.log('📭 No stored data found');
                this.hideDataUI();
                return;
            }
            
            const parsedData = JSON.parse(storedData);
            
            if (!parsedData || !parsedData.data || !Array.isArray(parsedData.data) || parsedData.data.length === 0) {
                console.log('⚠️ Stored data is invalid or empty');
                this.hideDataUI();
                return;
            }
            
            console.log('✅ Found stored data from:', parsedData.timestamp);
            console.log('📊 Loading', parsedData.data.length, 'stored items');
            
            this.loadDataIntoApp(parsedData.data);
            
        } catch (error) {
            console.error('❌ Error loading stored data:', error);
            localStorage.removeItem('jsonViewerData');
            this.hideDataUI();
        }
    }

    loadReviewedItems() {
        try {
            const stored = localStorage.getItem('reviewedItems');
            this.reviewedItems = stored ? new Set(JSON.parse(stored)) : new Set();
            console.log('📋 Loaded', this.reviewedItems.size, 'reviewed items');
        } catch (error) {
            console.error('❌ Error loading reviewed items:', error);
            this.reviewedItems = new Set();
        }
    }

    saveReviewedItems() {
        try {
            localStorage.setItem('reviewedItems', JSON.stringify([...this.reviewedItems]));
        } catch (error) {
            console.error('❌ Error saving reviewed items:', error);
        }
    }

    showDataUI() {
        const summarySection = document.getElementById('summarySection');
        const noData = document.getElementById('noData');
        const uploadHint = document.getElementById('uploadHint');
        
        if (summarySection) summarySection.style.display = 'block';
        if (noData) noData.style.display = 'none';
        if (uploadHint) uploadHint.style.display = 'block';
    }

    hideDataUI() {
        const summarySection = document.getElementById('summarySection');
        const noData = document.getElementById('noData');
        const tableContainer = document.getElementById('tableContainer');
        const uploadHint = document.getElementById('uploadHint');
        
        if (summarySection) summarySection.style.display = 'none';
        if (noData) noData.style.display = 'block';
        if (uploadHint) uploadHint.style.display = 'none';
        
        if (tableContainer) {
            tableContainer.innerHTML = `
                <div class="no-data" id="noData">
                    <h3>No data loaded</h3>
                    <p>Please upload a JSON file to view the results</p>
                </div>
            `;
        }
    }

    clearAllData() {
        const message = `This will permanently remove:<br>
            • Your uploaded JSON file(s)<br>
            • All review marks<br>
            • All stored data<br><br>
            <strong>This action cannot be undone.</strong>`;

        this.showConfirmPopup(
            message,
            () => {
                console.log('🧹 Clearing all data...');
                
                // Clear localStorage
                localStorage.removeItem('jsonViewerData');
                localStorage.removeItem('reviewedItems');
                
                // Reset all app state
                this.data = [];
                this.filteredData = [];
                this.reviewedItems = new Set();
                this.currentReport = null;
                
                // Clear search input
                const searchInput = document.getElementById('globalSearch');
                if (searchInput) searchInput.value = '';
                
                // Clear all filter inputs
                document.querySelectorAll('[data-filter]').forEach(input => {
                    input.value = '';
                });
                
                // Update UI to show empty state
                this.hideDataUI();
                
                console.log('✅ All data cleared successfully');
                this.showPopup('All data has been cleared successfully!', 'success');
            },
            null,
            'warning'
        );
    }

    generateItemId(item) {
        return `${item.repo_url || ''}-${item.commit || ''}-${item.file_path || ''}-${item.raw_secret || ''}`;
    }

    updateSummary() {
        const totalSecrets = this.data.length;
        const uniqueRepos = new Set(this.data.map(item => item.repo_url)).size;
        const verifiedSecrets = this.data.filter(item => item.verified).length;
        const reviewedCount = this.data.filter(item => item.reviewed).length;

        const elements = {
            totalSecrets: document.getElementById('totalSecrets'),
            totalRepos: document.getElementById('totalRepos'),
            verifiedSecrets: document.getElementById('verifiedSecrets'),
            reviewedCount: document.getElementById('reviewedCount')
        };

        if (elements.totalSecrets) elements.totalSecrets.textContent = totalSecrets;
        if (elements.totalRepos) elements.totalRepos.textContent = uniqueRepos;
        if (elements.verifiedSecrets) elements.verifiedSecrets.textContent = verifiedSecrets;
        if (elements.reviewedCount) elements.reviewedCount.textContent = reviewedCount;

        // Update detector breakdown
        const detectorCounts = {};
        this.data.forEach(item => {
            const detector = item.detector || 'Unknown';
            detectorCounts[detector] = (detectorCounts[detector] || 0) + 1;
        });

        const detectorList = document.getElementById('detectorList');
        if (detectorList) {
            detectorList.innerHTML = Object.entries(detectorCounts)
                .sort(([,a], [,b]) => b - a)
                .map(([detector, count]) => `
                    <div class="detector-item">
                        <span>${detector}</span>
                        <span>${count}</span>
                    </div>
                `).join('');
        }
    }

    renderTable() {
        const container = document.getElementById('tableContainer');
        if (!container) return;
        
        if (this.filteredData.length === 0) {
            if (this.data.length === 0) {
                this.hideDataUI();
            } else {
                container.innerHTML = '<div class="no-data"><h3>No matching results</h3><p>Try adjusting your search filters</p></div>';
            }
            return;
        }

        const table = document.createElement('table');
        table.className = 'data-table';
        
        // Create header
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>✓</th>
                <th>Repository</th>
                <th>Author</th>
                <th>Commit</th>
                <th>Filename</th>
                <th>Secret</th>
                <th>Detector</th>
                <th>Verified</th>
                <th>Actions</th>
            </tr>
            <tr class="filter-row">
                <td></td>
                <td><input type="text" placeholder="Filter repo..." data-filter="repo"></td>
                <td><input type="text" placeholder="Filter author..." data-filter="author"></td>
                <td><input type="text" placeholder="Filter commit..." data-filter="commit"></td>
                <td><input type="text" placeholder="Filter filename..." data-filter="filename"></td>
                <td><input type="text" placeholder="Filter secret..." data-filter="secret"></td>
                <td><input type="text" placeholder="Filter detector..." data-filter="detector"></td>
                <td></td>
                <td></td>
            </tr>
        `;

        // Create body
        const tbody = document.createElement('tbody');
        tbody.innerHTML = this.filteredData.map(item => this.createTableRow(item)).join('');

        table.appendChild(thead);
        table.appendChild(tbody);
        container.innerHTML = '';
        container.appendChild(table);

        // Add event listeners
        this.addTableEventListeners(table);
    }

    addTableEventListeners(table) {
        // Filter inputs
        table.querySelectorAll('[data-filter]').forEach(input => {
            input.addEventListener('input', (e) => this.handleColumnFilter(e.target.dataset.filter, e.target.value));
        });

        // Review checkboxes
        table.querySelectorAll('.review-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const id = parseInt(e.target.dataset.id);
                this.toggleReview(id);
            });
        });
    }

    createTableRow(item) {
        const repoName = this.extractRepoName(item.repo_url);
        const authorName = this.extractAuthorName(item.email);
        const shortCommit = (item.commit || '').substring(0, 8);
        const fileName = this.extractFileName(item.file_path);
        const shortSecret = (item.raw_secret || '').substring(0, 16) + '...';

        return `
            <tr class="${item.reviewed ? 'reviewed-row' : ''}">
                <td>
                    <input type="checkbox" class="review-checkbox" 
                           data-id="${item.id}" ${item.reviewed ? 'checked' : ''}>
                </td>
                <td>
                    <a href="${item.repo_url}" target="_blank" class="repo-link" title="${item.repo_url}">
                        ${repoName}
                    </a>
                </td>
                <td title="${item.email}">${authorName}</td>
                <td title="${item.commit}">
                    <a href="${item.commit_url}" target="_blank" class="repo-link">
                        ${shortCommit}
                    </a>
                </td>
                <td title="${item.file_path}">${fileName}</td>
                <td title="${item.raw_secret}">${shortSecret}</td>
                <td>
                    <span class="detector-badge">${item.detector || 'Unknown'}</span>
                </td>
                <td>
                    <span class="${item.verified ? 'verified-badge' : 'unverified-badge'}">
                        ${item.verified ? 'Yes' : 'No'}
                    </span>
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="btn-sm btn-report" onclick="generateReport(${item.id})">🐛 Report</button>
                    </div>
                </td>
            </tr>
        `;
    }

    extractRepoName(url) {
        if (!url) return 'Unknown';
        const parts = url.split('/');
        return parts.length >= 2 ? parts[parts.length - 1] : url;
    }

    extractAuthorName(email) {
        if (!email) return 'Unknown';
        const match = email.match(/^([^<]+)/);
        return match ? match[1].trim() : email.split('@')[0];
    }

    extractFileName(path) {
        if (!path) return 'Unknown';
        return path.split('/').pop();
    }

    handleGlobalSearch(query) {
        if (!query.trim()) {
            this.filteredData = [...this.data];
        } else {
            const searchTerm = query.toLowerCase();
            this.filteredData = this.data.filter(item => 
                JSON.stringify(item).toLowerCase().includes(searchTerm)
            );
        }
        this.renderTable();
    }

    handleColumnFilter(column, value) {
        const filters = {};
        document.querySelectorAll('[data-filter]').forEach(input => {
            if (input.value.trim()) {
                filters[input.dataset.filter] = input.value.toLowerCase();
            }
        });

        this.filteredData = this.data.filter(item => {
            return Object.entries(filters).every(([key, value]) => {
                switch (key) {
                    case 'repo':
                        return (item.repo_url || '').toLowerCase().includes(value);
                    case 'author':
                        return (item.email || '').toLowerCase().includes(value);
                    case 'commit':
                        return (item.commit || '').toLowerCase().includes(value);
                    case 'filename':
                        return (item.file_path || '').toLowerCase().includes(value);
                    case 'secret':
                        return (item.raw_secret || '').toLowerCase().includes(value);
                    case 'detector':
                        return (item.detector || '').toLowerCase().includes(value);
                    default:
                        return true;
                }
            });
        });
        this.renderTable();
    }

    toggleReview(id) {
        const item = this.data.find(item => item.id === id);
        if (!item) return;

        item.reviewed = !item.reviewed;
        const itemId = this.generateItemId(item);
        
        if (item.reviewed) {
            this.reviewedItems.add(itemId);
        } else {
            this.reviewedItems.delete(itemId);
        }
        
        this.saveReviewedItems();
        this.updateSummary();
        this.renderTable();
    }

    exportData() {
        if (this.data.length === 0) {
            this.showPopup('No data to export. Please upload a JSON file first.', 'warning');
            return;
        }

        const exportData = {
            summary: {
                totalSecrets: this.data.length,
                reviewedCount: this.data.filter(item => item.reviewed).length,
                exportDate: new Date().toISOString()
            },
            reviewed: this.data.filter(item => item.reviewed),
            unreviewed: this.data.filter(item => !item.reviewed),
            all: this.data
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_scan_export_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showPopup('Data exported successfully!', 'success');
    }

    showReport(id) {
        const item = this.data.find(item => item.id === id);
        if (!item) return;

        const report = generateBugBountyReport(item);
        
        const elements = {
            title: document.getElementById('reportTitle'),
            summary: document.getElementById('reportSummary'),
            poc: document.getElementById('reportPOC'),
            impact: document.getElementById('reportImpact'),
            severityBadge: document.getElementById('severityBadge'),
            modal: document.getElementById('reportModal')
        };

        if (elements.title) elements.title.value = report.title;
        if (elements.summary) elements.summary.value = report.summary;
        if (elements.poc) elements.poc.value = report.poc;
        if (elements.impact) elements.impact.value = report.impact;
        
        if (elements.severityBadge) {
            elements.severityBadge.textContent = report.severity;
            elements.severityBadge.className = `severity-badge severity-${report.severity.toLowerCase()}`;
        }
        
        if (elements.modal) elements.modal.style.display = 'block';
        
        this.currentReport = report;
    }

    copyToClipboard(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const tempTextarea = document.createElement('textarea');
        tempTextarea.value = element.value;
        document.body.appendChild(tempTextarea);
        tempTextarea.select();
        
        try {
            document.execCommand('copy');
            
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            button.classList.add('copy-success');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copy-success');
            }, 2000);
        } catch (err) {
            console.error('Failed to copy text: ', err);
        }
        
        document.body.removeChild(tempTextarea);
    }

    copyAllReport() {
        if (!this.currentReport) return;
        
        const fullReport = `${this.currentReport.title}\n\n## Summary\n${this.currentReport.summary}\n\n## Proof of Concept\n${this.currentReport.poc}\n\n## Impact\n${this.currentReport.impact}`;
        
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(fullReport).then(() => {
                this.showCopyFeedback('copyAllReport');
            }).catch(() => {
                this.fallbackCopyText(fullReport, 'copyAllReport');
            });
        } else {
            this.fallbackCopyText(fullReport, 'copyAllReport');
        }
    }

    fallbackCopyText(text, buttonId) {
        const tempTextarea = document.createElement('textarea');
        tempTextarea.value = text;
        document.body.appendChild(tempTextarea);
        tempTextarea.select();
        
        try {
            document.execCommand('copy');
            this.showCopyFeedback(buttonId);
        } catch (err) {
            console.error('Failed to copy text: ', err);
        }
        
        document.body.removeChild(tempTextarea);
    }

    showCopyFeedback(buttonId) {
        const btn = document.getElementById(buttonId);
        if (!btn) return;
        
        const originalText = btn.textContent;
        btn.textContent = '✅ Copied All!';
        btn.classList.add('copy-success');
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('copy-success');
        }, 2000);
    }

    downloadReport() {
        if (!this.currentReport) return;
        
        const content = `# ${this.currentReport.title}\n\n## Summary\n${this.currentReport.summary}\n\n## Proof of Concept\n${this.currentReport.poc}\n\n## Impact\n${this.currentReport.impact}`;
        
        const blob = new Blob([content], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `bug_bounty_report_${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showPopup('Report downloaded successfully!', 'success');
    }
}

// Global function for report generation
function generateReport(id) {
    if (window.jsonViewer) {
        window.jsonViewer.showReport(id);
    }
}

// Robust initialization
function initializeApp() {
    console.log('🚀 Initializing JSON Viewer App...');
    
    if (window.jsonViewer) {
        console.log('⚠️ App already initialized');
        return;
    }
    
    window.jsonViewer = new JSONViewer();
    console.log('✅ JSON Viewer initialized successfully');
}

// Multiple initialization approaches
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    // DOM is already ready
    setTimeout(initializeApp, 100);
}

// Backup initialization
window.addEventListener('load', () => {
    if (!window.jsonViewer) {
        console.log('🔄 Backup initialization...');
        initializeApp();
    }
});
