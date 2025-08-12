// Fix for investigation history persistence issue
// This script patches the loadInvestigations function to properly handle authenticated users

// Clean logout function - should not load demo data
function logout() {
    authToken = null;
    currentUser = null;
    isAuthenticated = false;
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    updateAuthUI();
    console.log('User logged out');
    // Do NOT reload investigations here - let the auth gate handle this
}

// Fixed loadInvestigations function
async function loadInvestigations() {
    try {
        ensureInvestigationsArray();
        
        if (isAuthenticated) {
            // Authenticated users: Load ONLY from server, ignore localStorage and demo data
            console.log('Loading authenticated user investigations');
            const response = await authenticatedFetch('/api/v1/simple_investigations/');
            if (response.ok) {
                const data = await response.json();
                const apiInvestigations = data.investigations || [];
                
                // For authenticated users, replace investigations with fresh data from API
                investigations = apiInvestigations.map(apiInv => ({
                    ...apiInv,
                    type: apiInv.investigation_type,
                    priority: 'normal',
                    investigator: currentUser.email,
                    report_generated: false
                }));
                console.log(`Loaded ${investigations.length} authenticated investigations`);
                
                // Display and exit immediately - no demo data logic
                updateInvestigationDisplay();
                return;
            } else if (response.status === 401) {
                console.log('Authentication expired, logging out');
                logout();
                return;
            }
        } else {
            // Demo users: Load from localStorage and API demo data
            const stored = localStorage.getItem('osint_investigations');
            if (stored) {
                try {
                    investigations = JSON.parse(stored);
                    ensureInvestigationsArray();
                } catch (e) {
                    console.error('Error parsing localStorage data:', e);
                    investigations = [];
                }
            }
            
            // Load demo data only if not already loaded
            const demoLoadedFlag = localStorage.getItem('demo_data_loaded');
            if (demoLoadedFlag !== 'true') {
                console.log('Loading demo data from API (first time only)');
                const response = await fetch('/api/v1/demo/investigations');
                if (response.ok) {
                    const data = await response.json();
                    const apiInvestigations = data.investigations || [];
                    
                    // Add demo investigations without duplicates
                    apiInvestigations.forEach(apiInv => {
                        const existing = investigations.find(inv => 
                            inv.id === apiInv.id || inv.target === apiInv.target
                        );
                        if (!existing) {
                            apiInv.type = apiInv.investigation_type;
                            apiInv.priority = 'normal';
                            apiInv.investigator = 'Demo System';
                            apiInv.report_generated = false;
                            delete apiInv.report_generated_at;
                            investigations.push(apiInv);
                        }
                    });
                    localStorage.setItem('demo_data_loaded', 'true');
                }
            }
            
            // Clean up duplicates and display
            removeDuplicateInvestigations();
            updateInvestigationDisplay();
        }
        
    } catch (error) {
        console.error('Error loading investigations:', error);
    }
}

console.log('Investigation fix script loaded');