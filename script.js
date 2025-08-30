class EnhancedJSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.reviewedItems = new Set();
        this.currentReport = null;
        this.sortState = { column: null, direction: 'asc' };
        this.filterState = { type: 'all', detector: 'all' };
        this.searchTerm = '';
        
        console.log('🚀 Enhanced JSONViewer initializing...');
        
        this.initializeApp();
    }

    initializeApp() {
        this.setupEventListeners();
        this.loadStoredData();
        this.loadReviewedItems();
        this.updateUI();
    }

    setupEventListeners() {
        // File upload
        const fileInput = document.getElementById('fileInput');
        const uploadArea = document.getElementById('uploadArea');
        
        uploadArea?.addEventListener('click', () => fileInput?.click());
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
            if (files.length > 0) this.processFile(files[0]);
        });

        // Enhanced search
        const searchInput = document.getElementById('globalSearch');
        const clearSearch = document.getElementById('clearSearch');
        
        searchInput?.addEventListener('input', this.debounce((e) => {
            this.handleSearch(e.target.value);
        }, 300));
        
        clearSearch?.addEventListener('click', () => {
            searchInput.value = '';
            this.handleSearch('');
        });

        // Sorting and filtering
        document.getElementById('sortSelect')?.addEventListener('change', (e) => {
            this.handleSort(e.target.value);
        });
        
        document.getElementById('filterSelect')?.addEventListener('change', (e) => {
            this.handleFilter(e.target.value);
        });
        
        document.getElementById('detectorFilter')?.addEventListener('change', (e) => {
            this.handleDetectorFilter(e.target.value);
        });

        // Control buttons
        document.getElementById('clearReviewed')?.addEventListener('click', () => {
            this.showConfirmDialog('Clear all review marks?', () => this.clearAllReviews());
        });
        
        document.getElementById('exportData')?.addEventListener('click', () => this.exportData());

        // Modal events
        this.setupModalEvents();
    }

    setupModalEvents() {
        const modal = document.getElementById('reportModal');
        const closeBtn = document.getElementById('closeModal');
        const copyAllBtn = document.getElementById('copyAllReport');
        const downloadBtn = document.getElementById('downloadReport');

        closeBtn?.addEventListener('click', () => this.hideModal());
        copyAllBtn?.addEventListener('click', () => this.copyAllReport());
        downloadBtn?.addEventListener('click', () => this.downloadReport());

        // Copy section buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-section-btn')) {
                const targetId = e.target.dataset.target;
                this.copySection(targetId, e.target);
            }
        });

        // Close modal on overlay click
        modal?.addEventListener('click', (e) => {
            if (e.target === modal) this.hideModal();
        });
    }

    // Enhanced file processing
    async handleFileUpload(event) {
        const file = event.target.files[0];
        if (file) await this.processFile(file);
    }

    async processFile(file) {
        if (!this.validateFile(file)) return;

        try {
            this.showLoading('Processing file...');
            const text = await this.readFileAsync(file);
            const jsonData = JSON.parse(text);
            const dataArray = Array.isArray(jsonData) ? jsonData : [jsonData];
            
            if (this.data.length > 0) {
                this.showAppendDialog(dataArray);
            } else {
                this.loadData(dataArray);
                this.showToast(`Loaded ${dataArray.length} security findings`, 'success');
            }
        } catch (error) {
            console.error('File processing error:', error);
            this.showToast(`Failed to process file: ${error.message}`, 'error');
        } finally {
            this.hideLoading();
        }
    }

    validateFile(file) {
        if (!file.name.toLowerCase().endsWith('.json')) {
            this.showToast('Please select a JSON file', 'error');
            return false;
        }
        
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
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
        const dialog = this.createDialog({
            title: 'Data Import Options',
            message: `You have ${this.data.length} existing items. How would you like to handle the new ${newData.length} items?`,
            buttons: [
                { text: 'Add to Top', class: 'btn-primary', action: () => this.appendData(newData, true) },
                { text: 'Replace All', class: 'btn-secondary', action: () => this.loadData(newData) },
                { text: 'Cancel', class: 'btn-ghost', action: () => {} }
            ]
        });
        
        this.showDialog(dialog);
    }

    // Enhanced data management
    loadData(rawData) {
        this.data = rawData.map((item, index) => ({
            ...item,
            id: `item_${Date.now()}_${index}`,
            reviewed: this.reviewedItems.has(this.generateItemId(item)),
            severity: this.calculateSeverity(item)
        }));
        
        this.applyFiltersAndSort();
        this.updateUI();
        this.saveToStorage();
        
        console.log(`✅ Loaded ${this.data.length} items`);
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
        // Enhanced severity calculation based on detector type and verification
        if (item.verified) return 'critical';
        
        const detectorType = (item.detector || '').toLowerCase();
        const highRiskDetectors = ['aws', 'slack', 'github', 'jwt', 'private-key'];
        const mediumRiskDetectors = ['api-key', 'password', 'token'];
        
        if (highRiskDetectors.some(d => detectorType.includes(d))) return 'high';
        if (mediumRiskDetectors.some(d => detectorType.includes(d))) return 'medium';
        
        return 'low';
    }

    // Enhanced search functionality
    handleSearch(query) {
        this.searchTerm = query.toLowerCase();
        this.applyFiltersAndSort();
        this.updateResultsCount();
    }

    // Enhanced sorting
    handleSort(sortType) {
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

    // Enhanced filtering
    handleFilter(filterType) {
        this.filterState.type = filterType;
        this.applyFiltersAndSort();
    }

    handleDetectorFilter(detector) {
        this.filterState.detector = detector;
        this.applyFiltersAndSort();
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

    // Enhanced UI updates
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

        document.getElementById('totalSecrets').textContent = stats.total;
        document.getElementById('verifiedSecrets').textContent = stats.verified;
        document.getElementById('reviewedCount').textContent = stats.reviewed;
        document.getElementById('totalRepos').textContent = stats.repos;

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
        
        document.getElementById('summarySection').style.display = hasData ? 'block' : 'none';
        document.getElementById('filtersBar').style.display = hasData ? 'flex' : 'none';
        document.getElementById('noDataState').style.display = hasData ? 'none' : 'flex';
    }

    // Enhanced table rendering
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
        const shortCommit = this.truncateText(item.commit, 8);

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

    // Enhanced review system
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

    clearAllReviews() {
        this.reviewedItems.clear();
        this.data.forEach(item => item.reviewed = false);
        this.saveReviewedItems();
        this.updateUI();
        this.showToast('All reviews cleared', 'success');
    }

    // Enhanced report generation
    generateReport(itemId) {
        const item = this.data.find(item => item.id === itemId);
        if (!item) return;

        // This would integrate with your detector-intelligence.js
        const report = this.createBugBountyReport(item);
        this.showReportModal(report);
    }

    createBugBountyReport(item) {
        // Basic report generation - enhance with detector-intelligence.js
        return {
            title: `Exposed ${item.detector || 'Secret'} in ${this.extractRepoName(item.repo_url)}`,
            summary: `A ${item.detector || 'secret'} was found exposed in the repository ${item.repo_url}. This could potentially allow unauthorized access to sensitive systems.`,
            poc: `The secret was found in the file: ${item.file_path}\n\nSecret value: ${item.raw_secret}\n\nComm
