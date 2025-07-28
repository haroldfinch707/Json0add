class JSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.reviewedItems = this.loadReviewedItems();
        this.currentReport = null;
        this.initEventListeners();
    }

    initEventListeners() {
        const fileInput = document.getElementById('fileInput');
        const uploadArea = document.getElementById('uploadArea');
        const globalSearch = document.getElementById('globalSearch');
        const clearReviewed = document.getElementById('clearReviewed');
        const exportData = document.getElementById('exportData');

        // File upload handlers
        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => this.handleFileUpload(e));

        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.processFile(files[0]);
            }
        });

        // Search and controls
        globalSearch.addEventListener('input', (e) => this.handleGlobalSearch(e.target.value));
        clearReviewed.addEventListener('click', () => this.clearAllReviews());
        exportData.addEventListener('click', () => this.exportData());

        // Modal event listeners
        this.initModalEventListeners();
    }

    initModalEventListeners() {
        const modal = document.getElementById('reportModal');
        const closeModal = document.getElementById('closeModal');
        const copyAllReport = document.getElementById('copyAllReport');
        const downloadReport = document.getElementById('downloadReport');

        // Close modal
        closeModal.addEventListener('click', () => {
            modal.style.display = 'none';
        });

        // Close modal when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });

        // Copy all report
        copyAllReport.addEventListener('click', () => this.copyAllReport());

        // Download report
        downloadReport.addEventListener('click', () => this.downloadReport());

        // Individual copy buttons - using event delegation since buttons are added dynamically
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
            alert('Please upload a JSON file');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const jsonData = JSON.parse(e.target.result);
                this.loadData(Array.isArray(jsonData) ? jsonData : [jsonData]);
            } catch (error) {
                alert('Invalid JSON file: ' + error.message);
            }
        };
        reader.readAsText(file);
    }

    loadData(data) {
        this.data = data.map((item, index) => ({
            ...item,
            id: index,
            reviewed: this.reviewedItems.has(this.generateItemId(item))
        }));
        this.filteredData = [...this.data];
        this.updateSummary();
        this.renderTable();
        document.getElementById('summarySection').style.display = 'block';
        document.getElementById('noData').style.display = 'none';
    }

    generateItemId(item) {
        return `${item.repo_url || ''}-${item.commit || ''}-${item.file_path || ''}-${item.raw_secret || ''}`;
    }

    updateSummary() {
        const totalSecrets = this.data.length;
        const uniqueRepos = new Set(this.data.map(item => item.repo_url)).size;
        const verifiedSecrets = this.data.filter(item => item.verified).length;
        const reviewedCount = this.data.filter(item => item.reviewed).length;

        document.getElementById('totalSecrets').textContent = totalSecrets;
        document.getElementById('totalRepos').textContent = uniqueRepos;
        document.getElementById('verifiedSecrets').textContent = verifiedSecrets;
        document.getElementById('reviewedCount').textContent = reviewedCount;

        // Update detector breakdown
        const detectorCounts = {};
        this.data.forEach(item => {
            const detector = item.detector || 'Unknown';
            detectorCounts[detector] = (detectorCounts[detector] || 0) + 1;
        });

        const detectorList = document.getElementById('detectorList');
        detectorList.innerHTML = Object.entries(detectorCounts)
            .sort(([,a], [,b]) => b - a)
            .map(([detector, count]) => `
                <div class="detector-item">
                    <span>${detector}</span>
                    <span>${count}</span>
                </div>
            `).join('');
    }

    renderTable() {
        const container = document.getElementById('tableContainer');
        
        if (this.filteredData.length === 0) {
            container.innerHTML = '<div class="no-data"><h3>No matching results</h3></div>';
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

        // Add filter event listeners
        table.querySelectorAll('[data-filter]').forEach(input => {
            input.addEventListener('input', (e) => this.handleColumnFilter(e.target.dataset.filter, e.target.value));
        });

        // Add review checkbox listeners
        table.querySelectorAll('.review-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => this.toggleReview(parseInt(e.target.dataset.id)));
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
        if (item) {
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
    }

    clearAllReviews() {
        if (confirm('Are you sure you want to clear all review marks?')) {
            this.reviewedItems.clear();
            this.data.forEach(item => item.reviewed = false);
            this.saveReviewedItems();
            this.updateSummary();
            this.renderTable();
        }
    }

    exportData() {
        const exportData = {
            summary: {
                totalSecrets: this.data.length,
                reviewedCount: this.data.filter(item => item.reviewed).length,
                exportDate: new Date().toISOString()
            },
            reviewed: this.data.filter(item => item.reviewed),
            unreviewed: this.data.filter(item => !item.reviewed)
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_scan_export_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    showReport(id) {
        const item = this.data.find(item => item.id === id);
        if (!item) return;

        const report = generateBugBountyReport(item);
        
        // Update modal content
        document.getElementById('reportTitle').value = report.title;
        document.getElementById('reportSummary').value = report.summary;
        document.getElementById('reportPOC').value = report.poc;
        document.getElementById('reportImpact').value = report.impact;
        
        // Update severity badge
        const severityBadge = document.getElementById('severityBadge');
        severityBadge.textContent = report.severity;
        severityBadge.className = `severity-badge severity-${report.severity.toLowerCase()}`;
        
        // Show modal
        document.getElementById('reportModal').style.display = 'block';
        
        // Store current report for copying/downloading
        this.currentReport = report;
    }

    copyToClipboard(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        // Create a temporary textarea to handle the copy operation
        const tempTextarea = document.createElement('textarea');
        tempTextarea.value = element.value;
        document.body.appendChild(tempTextarea);
        tempTextarea.select();
        
        try {
            document.execCommand('copy');
            
            // Visual feedback
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
        
        // Use modern clipboard API if available, fallback to older method
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
    }

    loadReviewedItems() {
        try {
            const stored = localStorage.getItem('reviewedItems');
            return stored ? new Set(JSON.parse(stored)) : new Set();
        } catch (error) {
            console.error('Error loading reviewed items:', error);
            return new Set();
        }
    }

    saveReviewedItems() {
        try {
            localStorage.setItem('reviewedItems', JSON.stringify([...this.reviewedItems]));
        } catch (error) {
            console.error('Error saving reviewed items:', error);
        }
    }
}

// Global functions
function generateReport(id) {
    if (window.jsonViewer) {
        window.jsonViewer.showReport(id);
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.jsonViewer = new JSONViewer();
});

// Fallback initialization
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        if (!window.jsonViewer) {
            window.jsonViewer = new JSONViewer();
        }
    });
} else {
    window.jsonViewer = new JSONViewer();
}
