class JSONViewer {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.reviewedItems = new Set();
        this.currentReport = null;
        
        console.log('🚀 JSONViewer constructor called');
        
        // Wait for DOM to be fully loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }

    initialize() {
        console.log('🎯 Initializing JSONViewer');
        
        // Small delay to ensure all elements are rendered
        setTimeout(() => {
            this.initEventListeners();
            this.loadReviewedItems();
            this.loadStoredData();
        }, 100);
    }

    initEventListeners() {
        console.log('🎯 Setting up event listeners');
        
        // File upload handlers - FIXED
        const fileInput = document.getElementById('fileInput');
        const uploadArea = document.getElementById('uploadArea');

        if (uploadArea && fileInput) {
            // Direct click handler
            uploadArea.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('Upload area clicked');
                fileInput.click();
            });

            // File input change handler
            fileInput.addEventListener('change', (e) => {
                console.log('File selected');
                this.handleFileUpload(e);
            });

            console.log('✅ Upload handlers attached');
        } else {
            console.error('❌ Upload elements not found');
        }

        // Drag and drop handlers - FIXED
        if (uploadArea) {
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadArea.classList.add('dragover');
            });

            uploadArea.addEventListener('dragleave', (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadArea.classList.remove('dragover');
            });

            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                uploadArea.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    console.log('File dropped');
                    this.processFile(files[0]);
                }
            });
        }

        // Search handlers - FIXED
        const globalSearch = document.getElementById('globalSearch');
        const clearSearch = document.getElementById('clearSearch');

        if (globalSearch) {
            globalSearch.addEventListener('input', (e) => {
                this.handleGlobalSearch(e.target.value);
            });
        }

        if (clearSearch) {
            clearSearch.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Clear search clicked');
                globalSearch.value = '';
                this.handleGlobalSearch('');
            });
        }

        // Control buttons - FIXED
        const clearReviewed = document.getElementById('clearReviewed');
        const exportData = document.getElementById('exportData');

        if (clearReviewed) {
            clearReviewed.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Clear reviewed clicked');
                this.clearAllData();
            });
        }

        if (exportData) {
            exportData.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Export data clicked');
                this.exportData();
            });
        }

        // Filter handlers - FIXED
        const sortSelect = document.getElementById('sortSelect');
        const filterSelect = document.getElementById('filterSelect');
        const detectorFilter = document.getElementById('detectorFilter');

        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                console.log('Sort changed:', e.target.value);
                this.handleSort(e.target.value);
            });
        }

        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                console.log('Filter changed:', e.target.value);
                this.handleFilter(e.target.value);
            });
        }

        if (detectorFilter) {
            detectorFilter.addEventListener('change', (e) => {
                console.log('Detector filter changed:', e.target.value);
                this.handleDetectorFilter(e.target.value);
            });
        }

        // Modal event listeners
        this.initModalEventListeners();
        
        console.log('✅ All event listeners initialized');
    }

    initModalEventListeners() {
        const modal = document.getElementById('reportModal');
        const closeModal = document.getElementById('closeModal');
        const copyAllReport = document.getElementById('copyAllReport');
        const downloadReport = document.getElementById('downloadReport');

        if (closeModal) {
            closeModal.addEventListener('click', (e) => {
                e.preventDefault();
                if (modal) modal.style.display = 'none';
            });
        }

        if (copyAllReport) {
            copyAllReport.addEventListener('click', (e) => {
                e.preventDefault();
                this.copyAllReport();
            });
        }

        if (downloadReport) {
            downloadReport.addEventListener('click', (e) => {
                e.preventDefault();
                this.downloadReport();
            });
        }

        // Close modal on overlay click
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }

        // Individual copy buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-btn') || e.target.classList.contains('copy-section-btn')) {
                e.preventDefault();
                const targetId = e.target.dataset.target;
                this.copyToClipboard(targetId, e.target);
            }
        });
    }

    // Rest of your existing methods...
    handleFileUpload(event) {
        const file = event.target.files[0];
        if (file) {
            console.log('Processing file:', file.name);
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
                const newDataArray = Array.isArray(jsonData) ? jsonData : [jsonData];
                
                console.log('📁 Processing new file with', newDataArray.length, 'items');
                
                if (this.data.length > 0) {
                    const append = confirm(`You have ${this.data.length} existing items. Add new data to top? (Cancel to replace all)`);
                    if (append) {
                        this.appendDataToTop(newDataArray);
                    } else {
                        this.loadDataIntoApp(newDataArray);
                        this.saveToLocalStorage(newDataArray);
                    }
                } else {
                    this.loadDataIntoApp(newDataArray);
                    this.saveToLocalStorage(newDataArray);
                }
                
            } catch (error) {
                console.error('❌ JSON parsing error:', error);
                alert(`Invalid JSON file: ${error.message}`);
            }
        };
        reader.readAsText(file);
    }

    // Add your other existing methods here...
    loadDataIntoApp(rawData) {
        console.log('📊 Loading data into app:', rawData.length, 'items');
        
        this.data = rawData.map((item, index) => ({
            ...item,
            id: index,
            reviewed: this.reviewedItems.has(this.generateItemId(item))
        }));
        
        this.filteredData = [...this.data];
        this.updateSummary();
        this.renderTable();
        this.showDataUI();
        
        console.log('✅ Data loaded successfully');
    }

    showDataUI() {
        const summarySection = document.getElementById('summarySection');
        const noData = document.getElementById('noDataState');
        const filtersBar = document.getElementById('filtersBar');
        
        if (summarySection) summarySection.style.display = 'block';
        if (noData) noData.style.display = 'none';
        if (filtersBar) filtersBar.style.display = 'flex';
    }

    // Add more methods as needed...
    generateItemId(item) {
        return `${item.repo_url || ''}-${item.commit || ''}-${item.file_path || ''}-${item.raw_secret || ''}`;
    }

    updateSummary() {
        // Update summary stats
        document.getElementById('totalSecrets').textContent = this.data.length;
        document.getElementById('verifiedSecrets').textContent = this.data.filter(item => item.verified).length;
        document.getElementById('reviewedCount').textContent = this.data.filter(item => item.reviewed).length;
        document.getElementById('totalRepos').textContent = new Set(this.data.map(item => item.repo_url)).size;
    }

    renderTable() {
        // Basic table rendering - add your enhanced version here
        const container = document.getElementById('tableContainer');
        if (!container || this.filteredData.length === 0) return;

        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>✓</th>
                    <th>Repository</th>
                    <th>Detector</th>
                    <th>File</th>
                    <th>Secret</th>
                    <th>Verified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${this.filteredData.map(item => `
                    <tr>
                        <td><input type="checkbox" ${item.reviewed ? 'checked' : ''}></td>
                        <td>${item.repo_url || 'Unknown'}</td>
                        <td>${item.detector || 'Unknown'}</td>
                        <td>${item.file_path || 'Unknown'}</td>
                        <td>${(item.raw_secret || '').substring(0, 20)}...</td>
                        <td>${item.verified ? 'Yes' : 'No'}</td>
                        <td><button class="btn btn-sm">Report</button></td>
                    </tr>
                `).join('')}
            </tbody>
        `;
        
        container.innerHTML = '';
        container.appendChild(table);
    }

    // Stub methods - implement as needed
    handleGlobalSearch(query) { console.log('Search:', query); }
    handleSort(type) { console.log('Sort:', type); }
    handleFilter(type) { console.log('Filter:', type); }
    handleDetectorFilter(detector) { console.log('Detector filter:', detector); }
    clearAllData() { console.log('Clear all data'); }
    exportData() { console.log('Export data'); }
    copyAllReport() { console.log('Copy all report'); }
    downloadReport() { console.log('Download report'); }
    copyToClipboard(targetId, button) { console.log('Copy to clipboard:', targetId); }
    
    // Storage methods
    saveToLocalStorage(data) {
        try {
            localStorage.setItem('jsonViewerData', JSON.stringify(data));
        } catch (error) {
            console.error('Failed to save to localStorage:', error);
        }
    }
    
    loadStoredData() {
        try {
            const stored = localStorage.getItem('jsonViewerData');
            if (stored) {
                const data = JSON.parse(stored);
                this.loadDataIntoApp(data);
            }
        } catch (error) {
            console.error('Failed to load stored data:', error);
        }
    }
    
    loadReviewedItems() {
        try {
            const stored = localStorage.getItem('reviewedItems');
            this.reviewedItems = stored ? new Set(JSON.parse(stored)) : new Set();
        } catch (error) {
            console.error('Failed to load reviewed items:', error);
            this.reviewedItems = new Set();
        }
    }

    appendDataToTop(newData) {
        // Implement data appending logic
        console.log('Appending data to top:', newData.length, 'items');
    }
}

// Initialize the app
let jsonViewer;

function initializeApp() {
    console.log('🚀 Initializing JSON Viewer App...');
    
    if (window.jsonViewer) {
        console.log('⚠️ App already initialized');
        return;
    }
    
    jsonViewer = new JSONViewer();
    window.jsonViewer = jsonViewer;
    console.log('✅ JSON Viewer initialized successfully');
}

// Multiple initialization attempts
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

// Backup initialization
setTimeout(() => {
    if (!window.jsonViewer) {
        console.log('🔄 Backup initialization...');
        initializeApp();
    }
}, 500);
