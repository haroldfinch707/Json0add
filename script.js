class JSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.reviewedItems = new Set();
        this.currentReport = null;
        this.sortState = { column: null, direction: 'asc' };
        this.filterState = { type: 'all', detector: 'all' };
        
        console.log('🚀 JSONViewer initializing...');
        this.initializeApp();
    }

    initializeApp() {
        // Wait for DOM and detector-intelligence.js to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                setTimeout(() => this.setupApp(), 100);
            });
        } else {
            setTimeout(() => this.setupApp(), 100);
        }
    }

    setupApp() {
        console.log('🎯 Setting up app...');
        this.setupEventListeners();
        this.loadStoredData();
        this.loadReviewedItems();
        console.log('✅ App setup complete');
    }

    setupEventListeners() {
        console.log('🎯 Setting up event listeners...');
        
        // Upload area - CRITICAL FIX
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        if (uploadArea && fileInput) {
            // Multiple event bindings to ensure it works
            uploadArea.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('🖱️ Upload area clicked');
                fileInput.click();
            };
            
            uploadArea.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('🖱️ Upload area click event');
                fileInput.click();
            });
            
            // Keyboard support
            uploadArea.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    fileInput.click();
                }
            });
            
            fileInput.addEventListener('change', (e) => {
                console.log('📁 File selected');
                this.handleFileUpload(e);
            });
            
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
                    console.log('📁 File dropped');
                    this.processFile(files[0]);
                }
            });
            
            console.log('✅ Upload area events attached');
        }
        
        // Search functionality
        const searchInput = document.getElementById('globalSearch');
        const clearSearch = document.getElementById('clearSearch');
        
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.handleSearch(e.target.value);
            });
        }
        
        if (clearSearch) {
            clearSearch.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('🔍 Clear search clicked');
                searchInput.value = '';
                this.handleSearch('');
            });
        }
        
        // Control buttons
        const clearBtn = document.getElementById('clearReviewed');
        const exportBtn = document.getElementById('exportData');
        
        if (clearBtn) {
            clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('🧹 Clear reviews clicked');
                this.clearAllData();
            });
        }
        
        if (exportBtn) {
            exportBtn.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('📤 Export clicked');
                this.exportData();
            });
        }
        
        // Filter dropdowns
        const sortSelect = document.getElementById('sortSelect');
        const filterSelect = document.getElementById('filterSelect');
        const detectorFilter = document.getElementById('detectorFilter');
        
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                console.log('🔄 Sort changed:', e.target.value);
                this.handleSort(e.target.value);
            });
        }
        
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                console.log('🔍 Filter changed:', e.target.value);
                this.handleFilter(e.target.value);
            });
        }
        
        if (detectorFilter) {
            detectorFilter.addEventListener('change', (e) => {
                console.log('🔍 Detector filter changed:', e.target.value);
                this.handleDetectorFilter(e.target.value);
            });
        }
        
        // Modal events
        this.setupModalEvents();
        
        console.log('✅ All event listeners attached');
    }

    setupModalEvents() {
        const modal = document.getElementById('reportModal');
        const closeBtn = document.getElementById('closeModal');
        const copyAllBtn = document.getElementById('copyAllReport');
        const downloadBtn = document.getElementById('downloadReport');

        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideModal());
        }
        
        if (copyAllBtn) {
            copyAllBtn.addEventListener('click', () => this.copyAllReport());
        }
        
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => this.downloadReport());
        }

        // Copy section buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-section-btn')) {
                const targetId = e.target.dataset.target;
                this.copySection(targetId, e.target);
            }
        });

        // Close modal on overlay click
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal || e.target.classList.contains('modal-overlay')) {
                    this.hideModal();
                }
            });
        }
    }

    handleFileUpload(event) {
        const file = event.target.files[0];
        if (file) {
            console.log('📁 Processing file:', file.name);
            this.processFile(file);
        }
    }

    async processFile(file) {
        if (!this.validateFile(file)) return;

        try {
            console.log('📊 Reading file...');
            const text = await this.readFileAsync(file);
            const jsonData = JSON.parse(text);
            const dataArray = Array.isArray(jsonData) ? jsonData : [jsonData];
            
            console.log('📊 Loaded', dataArray.length, 'items from file');
            
            if (this.data.length > 0) {
                this.showAppendDialog(dataArray);
            } else {
                this.loadData(dataArray);
                this.showToast(`Loaded ${dataArray.length} security findings`, 'success');
            }
        } catch (error) {
            console.error('❌ File processing error:', error);
            this.showToast(`Failed to process file: ${error.message}`, 'error');
        }
    }

    validateFile(file) {
        if (!file.name.toLowerCase().endsWith('.json')) {
            this.showToast('Please select a JSON file', 'error');
            return false;
        }
        
        if (file.size > 10 * 1024 * 1024) {
            this.showToast('File too large. Maximum size is 10MB', 'error');
            return false;
        }
        
        return true;
    }

    readFileAsync(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    showAppendDialog(newData) {
        const result = confirm(
            `You have ${this.data.length} existing items.\n\n` +
            `Click OK to ADD ${newData.length} new items to the top.\n` +
            `Click Cancel to REPLACE all existing data.`
        );
        
        if (result) {
            this.appendData(newData, true);
        } else {
            this.loadData(newData);
        }
    }

    loadData(rawData) {
        console.log('📊 Loading', rawData.length, 'items into app');
        
        this.data = rawData.map((item, index) => ({
            ...item,
            id: `item_${Date.now()}_${index}`,
            reviewed: this.reviewedItems.has(this.generateItemId(item)),
            severity: this.calculateSeverity(item)
        }));
        
        this.applyFiltersAndSort();
        this.updateUI();
        this.saveToStorage();
        
        console.log('✅ Data loaded successfully');
    }

    appendData(newData, prepend = true) {
        const processedNewData = newData.map((item, index) => ({
            ...item,
            id: `item_${Date.now()}_${index}`,
            reviewed: this.reviewedItems.has(this.generateItemId(item)),
            severity: this.calculateSeverity(item)
        }));
        
        this.data = prepend 
            ? [...processedNewData, ...this.data]
            : [...this.data, ...processedNewData];
        
        this.applyFiltersAndSort();
        this.updateUI();
        this.saveToStorage();
        
        this.showToast(`Added ${newData.length} new items${prepend ? ' to top' : ''}`, 'success');
    }

    calculateSeverity(item) {
        if (item.verified) return 'critical';
        
        const detectorType = (item.detector || '').toLowerCase();
        const highRiskDetectors = ['aws', 'slack', 'github', 'jwt', 'private-key'];
        const mediumRiskDetectors = ['api-key', 'password', 'token'];
        
        if (highRiskDetectors.some(d => detectorType.includes(d))) return 'high';
        if (mediumRiskDetectors.some(d => detectorType.includes(d))) return 'medium';
        
        return 'low';
    }

    // Search and filtering
    handleSearch(query) {
        console.log('🔍 Searching for:', query);
        this.searchTerm = query.toLowerCase();
        this.applyFiltersAndSort();
        this.updateResultsCount();
    }

    handleSort(sortType) {
        console.log('🔄 Sorting by:', sortType);
        switch (sortType) {
            case 'detector':
                this.sortBy('detector');
                break;
            case 'verified':
                this.sortBy('verified');
                break;
            case 'repo':
                this.sortBy('repo_url');
                break;
            case 'severity':
                this.sortBySeverity();
                break;
            default:
                this.sortState = { column: null, direction: 'asc' };
                this.applyFiltersAndSort();
        }
    }

    handleFilter(filterType) {
        console.log('🔍 Filtering by:', filterType);
        this.filterState.type = filterType;
        this.applyFiltersAndSort();
    }

    handleDetectorFilter(detector) {
        console.log('🔍 Detector filter:', detector);
        this.filterState.detector = detector;
        this.applyFiltersAndSort();
    }

    sortBy(column) {
        if (this.sortState.column === column) {
            this.sortState.direction = this.sortState.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortState = { column, direction: 'asc' };
        }
        
        this.applyFiltersAndSort();
    }

    sortBySeverity() {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        this.filteredData.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);
        this.renderTable();
    }

    applyFiltersAndSort() {
        let filtered = [...this.data];
        
        // Apply search
        if (this.searchTerm) {
            filtered = filtered.filter(item => 
                this.searchInItem(item, this.searchTerm)
            );
        }
        
        // Apply type filter
        if (this.filterState.type !== 'all') {
            filtered = filtered.filter(item => {
                switch (this.filterState.type) {
                    case 'verified': return item.verified;
                    case 'unverified': return !item.verified;
                    case 'reviewed': return item.reviewed;
                    case 'unreviewed': return !item.reviewed;
                    default: return true;
                }
            });
        }
        
        // Apply detector filter
        if (this.filterState.detector !== 'all') {
            filtered = filtered.filter(item => 
                (item.detector || '').toLowerCase() === this.filterState.detector.toLowerCase()
            );
        }
        
        // Apply sorting
        if (this.sortState.column) {
            filtered.sort((a, b) => {
                const aVal = a[this.sortState.column] || '';
                const bVal = b[this.sortState.column] || '';
                
                const result = aVal.toString().localeCompare(bVal.toString());
                return this.sortState.direction === 'asc' ? result : -result;
            });
        }
        
        this.filteredData = filtered;
        this.renderTable();
        this.updateResultsCount();
    }

    searchInItem(item, term) {
        const searchFields = [
            'repo_url', 'file_path', 'raw_secret', 'detector', 
            'email', 'commit', 'author'
        ];
        
        return searchFields.some(field => {
            const value = item[field];
            return value && value.toString().toLowerCase().includes(term);
        });
    }

    // UI Updates
    updateUI() {
        this.updateSummary();
        this.updateDetectorFilters();
        this.renderTable();
        this.updateResultsCount();
        this.toggleDataVisibility();
    }

    updateSummary() {
        const stats = {
            total: this.data.length,
            verified: this.data.filter(item => item.verified).length,
            reviewed: this.data.filter(item => item.reviewed).length,
            repos: new Set(this.data.map(item => item.repo_url)).size
        };

        this.updateElement('totalSecrets', stats.total);
        this.updateElement('verifiedSecrets', stats.verified);
        this.updateElement('reviewedCount', stats.reviewed);
        this.updateElement('totalRepos', stats.repos);

        this.updateDetectorBreakdown();
    }

    updateDetectorBreakdown() {
        const detectors = {};
        this.data.forEach(item => {
            const detector = item.detector || 'Unknown';
            detectors[detector] = (detectors[detector] || 0) + 1;
        });

        const listElement = document.getElementById('detectorList');
        if (listElement) {
            listElement.innerHTML = Object.entries(detectors)
                .sort(([,a], [,b]) => b - a)
                .map(([detector, count]) => `
                    <div class="detector-item">
                        <span>${detector}</span>
                        <span class="count">${count}</span>
                    </div>
                `).join('');
        }
    }

    updateDetectorFilters() {
        const detectors = [...new Set(this.data.map(item => item.detector || 'Unknown'))].sort();
        const select = document.getElementById('detectorFilter');
        
        if (select) {
            select.innerHTML = '<option value="all">All Detectors</option>' +
                detectors.map(detector => 
                    `<option value="${detector}">${detector}</option>`
                ).join('');
        }
    }

    updateResultsCount() {
        const countElement = document.getElementById('resultsCount');
        if (countElement) {
            if (this.data.length === 0) {
                countElement.textContent = 'No data loaded';
            } else {
                const filtered = this.filteredData.length;
                const total = this.data.length;
                countElement.textContent = filtered === total 
                    ? `${total} results`
                    : `${filtered} of ${total} results`;
            }
        }
    }

    toggleDataVisibility() {
        const hasData = this.data.length > 0;
        
        this.toggleElement('summarySection', hasData);
        this.toggleElement('filtersBar', hasData);
        this.toggleElement('noDataState', !hasData);
        
        if (hasData) {
            const hint = document.getElementById('uploadHint');
            if (hint) hint.style.display = 'block';
        }
    }

    // Table rendering
    renderTable() {
        const container = document.getElementById('tableContainer');
        if (!container) return;

        if (this.filteredData.length === 0) {
            if (this.data.length > 0) {
                container.innerHTML = `
                    <div class="no-data-state">
                        <div class="no-data-icon">🔍</div>
                        <h3>No matching results</h3>
                        <p>Try adjusting your search or filter criteria</p>
                    </div>
                `;
            }
            return;
        }

        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = this.generateTableHTML();
        
        container.innerHTML = '';
        container.appendChild(table);
        
        this.attachTableEvents(table);
    }

    generateTableHTML() {
        const headers = [
            { key: 'reviewed', label: '✓', sortable: false },
            { key: 'repo_url', label: 'Repository', sortable: true },
            { key: 'detector', label: 'Detector', sortable: true },
            { key: 'file_path', label: 'File', sortable: true },
            { key: 'raw_secret', label: 'Secret', sortable: false },
            { key: 'verified', label: 'Verified', sortable: true },
            { key: 'severity', label: 'Severity', sortable: true },
            { key: 'actions', label: 'Actions', sortable: false }
        ];

        const headerRow = headers.map(h => {
            const sortClass = this.sortState.column === h.key 
                ? `sortable sort-${this.sortState.direction}` 
                : (h.sortable ? 'sortable' : '');
            
            return `<th class="${sortClass}" data-column="${h.key}">${h.label}</th>`;
        }).join('');

        const bodyRows = this.filteredData.map(item => this.generateTableRow(item)).join('');

        return `
            <thead>
                <tr>${headerRow}</tr>
            </thead>
            <tbody>${bodyRows}</tbody>
        `;
    }

    generateTableRow(item) {
        const repoName = this.extractRepoName(item.repo_url);
        const fileName = this.extractFileName(item.file_path);
        const shortSecret = this.truncateText(item.raw_secret, 20);

        return `
            <tr class="${item.reviewed ? 'reviewed-row' : ''}" data-id="${item.id}">
                <td>
                    <input type="checkbox" class="review-checkbox" 
                           data-id="${item.id}" ${item.reviewed ? 'checked' : ''}>
                </td>
                <td>
                    <a href="${item.repo_url}" target="_blank" class="repo-link" 
                       title="${item.repo_url}">${repoName}</a>
                </td>
                <td>
                    <span class="detector-badge">${item.detector || 'Unknown'}</span>
                </td>
                <td title="${item.file_path}">${fileName}</td>
                <td title="${item.raw_secret}">${shortSecret}</td>
                <td>
                    <span class="${item.verified ? 'verified-badge' : 'unverified-badge'}">
                        ${item.verified ? 'Yes' : 'No'}
                    </span>
                </td>
                <td>
                    <span class="severity-badge severity-${item.severity}">${item.severity}</span>
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-report" data-action="report" data-id="${item.id}">
                            🐛 Report
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }

    attachTableEvents(table) {
        // Sortable headers
        table.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.column;
                this.sortBy(column);
            });
        });

        // Review checkboxes
        table.querySelectorAll('.review-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const itemId = e.target.dataset.id;
                this.toggleReview(itemId);
            });
        });

        // Action buttons
        table.querySelectorAll('[data-action="report"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const itemId = e.target.dataset.id;
                this.generateReport(itemId);
            });
        });
    }

    // Report generation using detector-intelligence.js
    generateReport(itemId) {
        const item = this.data.find(item => item.id === itemId);
        if (!item) return;

        console.log('🐛 Generating report for item:', itemId);

        // Use detector-intelligence.js if available
        let report;
        if (typeof generateBugBountyReport === 'function') {
            try {
                report = generateBugBountyReport(item);
                console.log('✅ Report generated using detector-intelligence.js');
            } catch (error) {
                console.warn('⚠️ detector-intelligence.js failed, using fallback:', error);
                report = this.createFallbackReport(item);
            }
        } else {
            console.warn('⚠️ detector-intelligence.js not found, using fallback');
            report = this.createFallbackReport(item);
        }

        this.showReportModal(report);
    }

    createFallbackReport(item) {
        return {
            title: `Exposed ${item.detector || 'Secret'} in ${this.extractRepoName(item.repo_url)}`,
            summary: `A ${item.detector || 'secret'} was found exposed in the repository. This could potentially allow unauthorized access to sensitive systems.`,
            poc: `**Repository:** ${item.repo_url || 'Unknown'}\n**File Path:** ${item.file_path || 'Unknown'}\n**Commit:** ${item.commit || 'Unknown'}\n**Secret Type:** ${item.detector || 'Unknown'}\n\n**Evidence:**\nThe exposed secret was found in the codebase.`,
            impact: `The exposure of this ${item.detector || 'credential'} could result in:\n\n• Unauthorized access to systems or services\n• Data breach and potential data exfiltration\n• Service disruption\n• Financial losses\n• Compliance violations`,
            severity: item.verified ? 'critical' : 'high'
        };
    }

    showReportModal(report) {
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
        
        if (elements.modal) {
            elements.modal.style.display = 'block';
            elements.modal.classList.add('show');
        }
        
        this.currentReport = report;
    }

    hideModal() {
        const modal = document.getElementById('reportModal');
        if (modal) {
            modal.style.display = 'none';
            modal.classList.remove('show');
        }
    }

    // Review system
    toggleReview(itemId) {
        const item = this.data.find(item => item.id === itemId);
        if (!item) return;

        item.reviewed = !item.reviewed;
        const reviewId = this.generateItemId(item);
        
        if (item.reviewed) {
            this.reviewedItems.add(reviewId);
        } else {
            this.reviewedItems.delete(reviewId);
        }
        
        this.saveReviewedItems();
        this.updateSummary();
        this.applyFiltersAndSort();
    }

    clearAllData() {
        const result = confirm(
            'This will permanently remove:\n\n' +
            '• Your uploaded JSON file(s)\n' +
            '• All review marks\n' +
            '• All stored data\n\n' +
            'This action cannot be undone.\n\n' +
            'Are you sure you want to continue?'
        );

        if (result) {
            console.log('🧹 Clearing all data...');
            
            localStorage.removeItem('jsonViewerData');
            localStorage.removeItem('reviewedItems');
            
            this.data = [];
            this.filteredData = [];
            this.reviewedItems = new Set();
            this.currentReport = null;
            
            const searchInput = document.getElementById('globalSearch');
            if (searchInput) searchInput.value = '';
            
            this.updateUI();
            
            this.showToast('All data has been cleared successfully!', 'success');
        }
    }

    exportData() {
        if (this.data.length === 0) {
            this.showToast('No data to export. Please upload a JSON file first.', 'warning');
            return;
        }

        const exportData = {
            summary: {
                totalSecrets: this.data.length,
                reviewedCount: this.data
