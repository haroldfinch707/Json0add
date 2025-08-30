class JSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.displayedData = [];
        this.reviewedItems = new Set();
        this.currentReport = null;
        this.currentPage = 1;
        this.itemsPerPage = 100;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.activeQuickFilter = 'all';
        this.searchOptions = {
            caseSensitive: false,
            regex: false
        };
        
        console.log('🚀 JSONViewer constructor called');
        this.initEventListeners();
        
        setTimeout(() => {
            this.loadReviewedItems();
            this.loadStoredData();
        }, 200);
    }

    // Enhanced popup system
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
        setTimeout(() => popup.classList.add('show'), 10);
        
        if (!actions) {
            setTimeout(() => this.hidePopup(popup), 5000);
        }
        
        popup.querySelector('.popup-close').addEventListener('click', () => {
            this.hidePopup(popup);
        });
        
        return popup;
    }

    showConfirmPopup(message, onConfirm, onCancel = null, type = 'warning') {
        const actions = `
            <button class="popup-btn btn-danger" data-action="confirm">Yes, Continue</button>
            <button class="popup-btn btn-secondary" data-action="cancel">Cancel</button>
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
            <button class="popup-btn btn-primary" data-action="append">📎 Add to Top</button>
            <button class="popup-btn btn-secondary" data-action="replace">🔄 Replace All</button>
            <button class="popup-btn btn-secondary" data-action="cancel">❌ Cancel</button>
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
        const clearSearch = document.getElementById('clearSearch');
        const caseSensitive = document.getElementById('caseSensitive');
        const regexSearch = document.getElementById('regexSearch');
        const clearReviewed = document.getElementById('clearReviewed');
        const exportData = document.getElementById('exportData');
        const itemsPerPage = document.getElementById('itemsPerPage');
        const prevPage = document.getElementById('prevPage');
        const nextPage = document.getElementById('nextPage');

        // File upload handlers
        uploadArea?.addEventListener('click', () => fileInput.click());
        fileInput?.addEventListener('change', (e) => this.handleFileUpload(e));

        // Enhanced drag and drop
        uploadArea?.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea?.addEventListener('dragleave', (e) => {
            if (!uploadArea.contains(e.relatedTarget)) {
                uploadArea.classList.remove('dragover');
            }
        });

        uploadArea?.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = Array.from(e.dataTransfer.files).filter(file => 
                file.name.toLowerCase().endsWith('.json')
            );
            if (files.length > 0) {
                this.processMultipleFiles(files);
            } else {
                this.showPopup('Please drop only JSON files', 'error');
            }
        });

        // Enhanced search functionality
        let searchTimeout;
        globalSearch?.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this.handleGlobalSearch(e.target.value);
            }, 300);
        });

        clearSearch?.addEventListener('click', () => {
            globalSearch.value = '';
            this.handleGlobalSearch('');
        });

        caseSensitive?.addEventListener('change', (e) => {
            this.searchOptions.caseSensitive = e.target.checked;
            this.handleGlobalSearch(globalSearch?.value || '');
        });

        regexSearch?.addEventListener('change', (e) => {
            this.searchOptions.regex = e.target.checked;
            this.handleGlobalSearch(globalSearch?.value || '');
        });

        // Controls
        clearReviewed?.addEventListener('click', () => this.clearAllData());
        exportData?.addEventListener('click', () => this.exportData());

        // Pagination
        itemsPerPage?.addEventListener('change', (e) => {
            this.itemsPerPage = e.target.value === 'all' ? 'all' : parseInt(e.target.value);
            this.currentPage = 1;
            this.updateDisplayedData();
            this.renderTable();
            this.updatePagination();
        });

        prevPage?.addEventListener('click', () => {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.updateDisplayedData();
                this.renderTable();
                this.updatePagination();
            }
        });

        nextPage?.addEventListener('click', () => {
            const totalPages = this.getTotalPages();
            if (this.currentPage < totalPages) {
                this.currentPage++;
                this.updateDisplayedData();
                this.renderTable();
                this.updatePagination();
            }
        });

        // Quick filters
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-btn')) {
                this.handleQuickFilter(e.target.dataset.filter);
            }
        });

        // Modal handlers
        this.initModalEventListeners();

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                globalSearch?.focus();
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
                e.preventDefault();
                this.exportData();
            }
        });
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

        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-btn')) {
                const targetId = e.target.dataset.target;
                this.copyToClipboard(targetId, e.target);
            }
        });
    }

    handleFileUpload(event) {
        const files = Array.from(event.target.files).filter(file => 
            file.name.toLowerCase().endsWith('.json')
        );
        
        if (files.length === 0) {
            this.showPopup('Please select JSON files only', 'error');
            return;
        }

        this.processMultipleFiles(files);
    }

    async processMultipleFiles(files) {
        try {
            let allData = [];
            let processedCount = 0;

            for (const file of files) {
                try {
                    const data = await this.readFile(file);
                    const jsonData = JSON.parse(data);
                    const dataArray = Array.isArray(jsonData) ? jsonData : [jsonData];
                    allData.push(...dataArray);
                    processedCount++;
                } catch (error) {
                    console.error(`Error processing ${file.name}:`, error);
                    this.showPopup(`Error in ${file.name}: ${error.message}`, 'error');
                }
            }

            if (allData.length === 0) {
                this.showPopup('No valid data found in the uploaded files', 'error');
                return;
            }

            console.log('📁 Processing', allData.length, 'items from', processedCount, 'files');

            if (this.data.length > 0) {
                this.showAppendConfirmPopup(
                    this.data.length,
                    allData.length,
                    () => this.appendDataToTop(allData),
                    () => {
                        this.loadDataIntoApp(allData);
                        this.saveToLocalStorage(allData);
                    }
                );
            } else {
                this.loadDataIntoApp(allData);
                this.saveToLocalStorage(allData);
            }

        } catch (error) {
            console.error('❌ File processing error:', error);
            this.showPopup(`Error processing files: ${error.message}`, 'error');
        }
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    appendDataToTop(newDataArray) {
        console.log('📎 Appending', newDataArray.length, 'new items to the top');
        
        const existingRawData = this.getRawDataArray();
        const combinedRawData = [...newDataArray, ...existingRawData];
        
        this.loadDataIntoApp(combinedRawData);
        this.saveToLocalStorage(combinedRawData);
        
        console.log('✅ Data appended successfully. Total items:', this.data.length);
        this.showPopup(
            `Added <strong>${newDataArray.length}</strong> new items to the top!<br>Total items: <strong>${this.data.length}</strong>`,
            'success'
        );
    }

    getRawDataArray() {
        return this.data.map(item => {
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
        this.currentPage = 1;
        this.updateDisplayedData();
        
        this.updateSummary();
        this.renderTable();
        this.updatePagination();
        this.showDataUI();
        
        console.log('✅ Data loaded successfully');
    }

    saveToLocalStorage(rawDataArray) {
        try {
            const storageData = {
                data: rawDataArray,
                timestamp: new Date().toISOString(),
                version: '1.1'
            };
            
            localStorage.setItem('jsonViewerData', JSON.stringify(storageData));
            console.log('💾 Data saved to localStorage');
            
        } catch (error) {
            console.error('❌ Failed to save to localStorage:', error);
            
            if (error.name === 'QuotaExceededError') {
                this.showPopup('Storage space full! Clearing old data...', 'warning');
                this.clearAllData();
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
            
            if (!parsedData?.data || !Array.isArray(parsedData.data) || parsedData.data.length === 0) {
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
        document.getElementById('summarySection')?.style.setProperty('display', 'block');
        document.getElementById('noData')?.style.setProperty('display', 'none');
        document.getElementById('uploadHint')?.style.setProperty('display', 'block');
        document.getElementById('pagination')?.style.setProperty('display', 'flex');
    }

    hideDataUI() {
        document.getElementById('summarySection')?.style.setProperty('display', 'none');
        document.getElementById('noData')?.style.setProperty('display', 'block');
        document.getElementById('uploadHint')?.style.setProperty('display', 'none');
        document.getElementById('pagination')?.style.setProperty('display', 'none');
        
        const tableContainer = document.getElementById('tableContainer');
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
                
                localStorage.removeItem('jsonViewerData');
                localStorage.removeItem('reviewedItems');
                
                this.data = [];
                this.filteredData = [];
                this.displayedData = [];
                this.reviewedItems = new Set();
                this.currentReport = null;
                this.currentPage = 1;
                this.activeQuickFilter = 'all';
                
                // Clear inputs
                const searchInput = document.getElementById('globalSearch');
                if (searchInput) searchInput.value = '';
                
                document.querySelectorAll('[data-filter]').forEach(input => {
                    input.value = '';
                });
                
                // Reset filter buttons
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                document.querySelector('.filter-btn[data-filter="all"]')?.classList.add('active');
                
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

        document.getElementById('totalSecrets')?.textContent = totalSecrets;
        document.getElementById('totalRepos')?.textContent = uniqueRepos;
        document.getElementById('verifiedSecrets')?.textContent = verifiedSecrets;
        document.getElementById('reviewedCount')?.textContent = reviewedCount;

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

    // Enhanced search with better performance and options
    handleGlobalSearch(query) {
        if (!query.trim()) {
            this.filteredData = [...this.data];
        } else {
            try {
                const searchTerm = this.searchOptions.caseSensitive ? query : query.toLowerCase();
                
                if (this.searchOptions.regex) {
                    const regex = new RegExp(searchTerm, this.searchOptions.caseSensitive ? 'g' : 'gi');
                    this.filteredData = this.data.filter(item => 
                        regex.test(JSON.stringify(item))
                    );
                } else {
                    this.filteredData = this.data.filter(item => {
                        const itemStr = this.searchOptions.caseSensitive ? 
                            JSON.stringify(item) : 
                            JSON.stringify(item).toLowerCase();
                        return itemStr.includes(searchTerm);
                    });
                }
            } catch (error) {
                // Invalid regex
                this.showPopup('Invalid regular expression', 'error');
                return;
            }
        }
        
        this.applyQuickFilter();
        this.currentPage = 1;
        this.updateDisplayedData();
        this.renderTable();
        this.updatePagination();
    }

    // Quick filter functionality
    handleQuickFilter(filter) {
        // Update active button
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`.filter-btn[data-filter="${filter}"]`)?.classList.add('active');
        
        this.activeQuickFilter = filter;
        this.applyQuickFilter();
        this.currentPage = 1;
        this.updateDisplayedData();
        this.renderTable();
        this.updatePagination();
    }

    applyQuickFilter() {
        let baseData = this.filteredData;
        
        switch (this.activeQuickFilter) {
            case 'verified':
                this.filteredData = baseData.filter(item => item.verified);
                break;
            case 'unverified':
                this.filteredData = baseData.filter(item => !item.verified);
                break;
            case 'reviewed':
                this.filteredData = baseData.filter(item => item.reviewed);
                break;
            case 'unreviewed':
                this.filteredData = baseData.filter(item => !item.reviewed);
                break;
            case 'all':
            default:
                // Already filtered by search, no additional filter needed
                break;
        }
    }

    // Pagination functionality
    getTotalPages() {
        if (this.itemsPerPage === 'all') return 1;
        return Math.ceil(this.filteredData.length / this.itemsPerPage);
    }

    updateDisplayedData() {
        if (this.itemsPerPage === 'all') {
            this.displayedData = [...this.filteredData];
        } else {
            const start = (this.currentPage - 1) * this.itemsPerPage;
            const end = start + this.itemsPerPage;
            this.displayedData = this.filteredData.slice(start, end);
        }
    }

    updatePagination() {
        const totalPages = this.getTotalPages();
        const pageInfo = document.getElementById('pageInfo');
        const prevBtn = document.getElementById('prevPage');
        const nextBtn = document.getElementById('nextPage');
        
        if (pageInfo) {
            if (this.itemsPerPage === 'all') {
                pageInfo.textContent = `Showing all ${this.filteredData.length} items`;
            } else {
                pageInfo.textContent = `Page ${this.currentPage} of ${totalPages} (${this.filteredData.length} items)`;
            }
        }
        
        if (prevBtn) prevBtn.disabled = this.currentPage <= 1 || this.itemsPerPage === 'all';
        if (nextBtn) nextBtn.disabled = this.currentPage >= totalPages || this.itemsPerPage === 'all';
    }

    // Enhanced table rendering with sorting
    renderTable() {
        const container = document.getElementById('tableContainer');
        if (!container) return;
        
        if (this.displayedData.length === 0) {
            if (this.data.length === 0) {
                this.hideDataUI();
            } else {
                container.innerHTML = '<div class="no-data"><h3>No matching results</h3><p>Try adjusting your search filters</p></div>';
            }
            return;
        }

        const table = document.createElement('table');
        table.className = 'data-table';
        
        // Create header with sorting
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>✓</th>
                <th class="sortable" data-sort="repo_url">Repository</th>
                <th class="sortable" data-sort="email">Author</th>
                <th class="sortable" data-sort="commit">Commit</th>
                <th class="sortable" data-sort="file_path">Filename</th>
                <th class="sortable" data-sort="raw_secret">Secret</th>
                <th class="sortable" data-sort="detector">Detector</th>
                <th class="sortable" data-sort="verified">Verified</th>
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

        // Update sort indicators
        const sortHeaders = thead.querySelectorAll('.sortable');
        sortHeaders.forEach(th => {
            if (th.dataset.sort === this.sortColumn) {
                th.classList.remove('sort-asc', 'sort-desc');
                th.classList.add(`sort-${this.sortDirection}`);
            } else {
                th.classList.remove('sort-asc', 'sort-desc');
            }
        });

        // Create body
        const tbody = document.createElement('tbody');
        tbody.innerHTML = this.displayedData.map(item => this.createTableRow(item)).join('');

        table.appendChild(thead);
        table.appendChild(tbody);
        container.innerHTML = '';
        container.appendChild(table);

        // Add event listeners
        this.addTableEventListeners(table);
    }

    addTableEventListeners(table) {
        // Sort handlers
        table.querySelectorAll('.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.sort;
                if (this.sortColumn === column) {
                    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortColumn = column;
                    this.sortDirection = 'asc';
                }
                this.sortData();
                this.updateDisplayedData();
                this.renderTable();
            });
        });

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

    sortData() {
        this.filteredData.sort((a, b) => {
            let aVal = a[this.sortColumn] || '';
            let bVal = b[this.sortColumn] || '';
            
            // Handle different data types
            if (typeof aVal === 'string') aVal = aVal.toLowerCase();
            if (typeof bVal === 'string') bVal = bVal.toLowerCase();
            
            if (this.sortColumn === 'verified') {
                aVal = a.verified ? 1 : 0;
                bVal = b.verified ? 1 : 0;
            }
            
            if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
            if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }

    createTableRow(item) {
        const repoName = this.extractRepoName(item.repo_url);
        const authorName = this.extractAuthorName(item.email);
        const shortCommit = (item.commit || '').substring(0, 8);
        const fileName = this.extractFileName(item.file_path);
        const shortSecret = (item.raw_secret || '').length > 16 ? 
            (item.raw_secret || '').substring(0, 16) + '...' : (item.raw_secret || '');

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
                <td title="${item.raw_secret}" class="secret-cell">${shortSecret}</td>
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
        try {
            const parts = url.replace(/\.git$/, '').split('/');
            return parts.length >= 2 ? parts[parts.length - 1] : url;
        } catch {
            return url;
        }
    }

    extractAuthorName(email) {
        if (!email) return 'Unknown';
        const match = email.match(/^([^<]+)/);
        return match ? match[1].trim() : email.split('@')[0];
    }

    extractFileName(path) {
        if (!path) return 'Unknown';
        return path.split('/').pop() || path;
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
        
        this.applyQuickFilter();
        this.currentPage = 1;
        this.updateDisplayedData();
        this.renderTable();
        this.updatePagination();
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
        
        // Update filtered data as well
        const filteredItem = this.filteredData.find(fItem => fItem.id === id);
        if (filteredItem) {
            filteredItem.reviewed = item.reviewed;
        }
        
        this.updateDisplayedData();
        this.renderTable();
    }

    exportData() {
        if (this.data.length === 0) {
            this.showPopup('No data to export. Please upload a JSON file first.', 'warning');
            return;
        }

        const exportData = {
            metadata: {
                totalSecrets: this.data.length,
                reviewedCount: this.data.filter(item => item.reviewed).length,
                verifiedCount: this.data.filter(item => item.verified).length,
                exportDate: new Date().toISOString(),
                version: '1.1'
            },
            summary: {
                detectors: this.getDetectorSummary(),
                repositories: this.getRepositorySummary()
            },
            data: {
                reviewed: this.data.filter(item => item.reviewed),
                unreviewed: this.data.filter(item => !item.reviewed),
                verified: this.data.filter(item => item.verified),
                unverified: this.data.filter(item => !item.verified),
                all: this.data
            }
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_scan_export_${new Date().toISOString().split('T')[0]}_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showPopup(`Data exported successfully!<br>Total: ${this.data.length} items`, 'success');
    }

    getDetectorSummary() {
        const summary = {};
        this.data.forEach(item => {
            const detector = item.detector || 'Unknown';
            if (!summary[detector]) {
                summary[detector] = { total: 0, verified: 0, reviewed: 0 };
            }
            summary[detector].total++;
            if (item.verified) summary[detector].verified++;
            if (item.reviewed) summary[detector].reviewed++;
        });
        return summary;
    }

    getRepositorySummary() {
        const summary = {};
        this.data.forEach(item => {
            const repo = item.repo_url || 'Unknown';
            if (!summary[repo]) {
                summary[repo] = { total: 0, verified: 0, reviewed: 0 };
            }
            summary[repo].total++;
            if (item.verified) summary[repo].verified++;
            if (item.reviewed) summary[repo].reviewed++;
        });
        return summary;
    }

    showReport(id) {
        const item = this.data.find(item => item.id === id);
        if (!item) return;

        // Check if detector-intelligence.js is available
        if (typeof generateBugBountyReport === 'function') {
            const report = generateBugBountyReport(item);
            this.displayReport(report);
        } else {
            // Fallback basic report
            const report = this.generateBasicReport(item);
            this.displayReport(report);
        }
    }

    generateBasicReport(item) {
        return {
            title: `Secret Exposure: ${item.detector || 'Unknown'} in ${this.extractRepoName(item.repo_url)}`,
            summary: `A ${item.detector || 'secret'} was discovered in the repository. This could potentially allow unauthorized access.`,
            poc: `Repository: ${item.repo_url}\nFile: ${item.file_path}\nCommit: ${item.commit}\nDetector: ${item.detector}\nVerified: ${item.verified ? 'Yes' : 'No'}`,
            impact: `This exposure could lead to unauthorized access to systems and data. Immediate remediation is recommended.`,
            severity: item.verified ? 'High' : 'Medium'
        };
    }

    displayReport(report) {
        document.getElementById('reportTitle').value = report.title;
        document.getElementById('reportSummary').value = report.summary;
        document.getElementById('reportPOC').value = report.poc;
        document.getElementById('reportImpact').value = report.impact;
        
        const severityBadge = document.getElementById('severityBadge');
        severityBadge.textContent = report.severity;
        severityBadge.className = `severity-badge severity-${report.severity.toLowerCase()}`;
        
        document.getElementById('reportModal').style.display = 'block';
        this.currentReport = report;
    }

    copyToClipboard(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        navigator.clipboard.writeText(element.value).then(() => {
            const originalText = button.textContent;
            button.textContent = '✅ Copied!';
            button.classList.add('copy-success');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copy-success');
            }, 2000);
        }).catch(() => {
            // Fallback for older browsers
            const tempTextarea = document.createElement('textarea');
            tempTextarea.value = element.value;
            document.body.appendChild(tempTextarea);
            tempTextarea.select();
            document.execCommand('copy');
            document.body.removeChild(tempTextarea);
            
            const originalText = button.textContent;
            button.textContent = '✅ Copied!';
            button.classList.add('copy-success');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copy-success');
            }, 2000);
        });
    }

    copyAllReport() {
        if (!this.currentReport) return;
        
        const fullReport = `${this.currentReport.title}\n\n## Summary\n${this.currentReport.summary}\n\n## Proof of Concept\n${this.currentReport.poc}\n\n## Impact\n${this.currentReport.impact}`;
        
        navigator.clipboard.writeText(fullReport).then(() => {
            this.showCopyFeedback('copyAllReport');
        }).catch(() => {
            this.fallbackCopyText(fullReport, 'copyAllReport');
        });
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
    window.jsonViewer?.showReport(id);
}

// Initialize app
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
    setTimeout(initializeApp, 100);
}

window.addEventListener('load', () => {
    if (!window.jsonViewer) {
        console.log('🔄 Backup initialization...');
        initializeApp();
    }
});
