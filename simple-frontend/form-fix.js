// Fix for investigation form submission to use authenticated endpoint

// Fixed investigation form submission
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('investigationForm');
    if (form) {
        // Remove existing event listeners and add new one
        form.replaceWith(form.cloneNode(true));
        const newForm = document.getElementById('investigationForm');
        
        newForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                target: document.getElementById('target').value,
                type: document.getElementById('type').value,
                priority: document.getElementById('priority').value,
                investigator: document.getElementById('investigator').value
            };
            
            try {
                const payload = {
                    target: formData.target,
                    investigation_type: formData.type
                };
                
                // Use authenticated endpoint for authenticated users
                const apiEndpoint = isAuthenticated ? '/api/v1/simple_investigations/' : '/api/v1/demo/investigations';
                
                const headers = {
                    'Content-Type': 'application/json',
                };
                
                // Add authorization header if authenticated
                if (isAuthenticated && authToken) {
                    headers['Authorization'] = `Bearer ${authToken}`;
                }
                
                const response = await fetch(apiEndpoint, {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify(payload)
                });
                
                if (response.ok) {
                    const investigation = await response.json();
                    
                    if (isAuthenticated) {
                        // For authenticated users, reload from server immediately
                        alert(`Investigation ${investigation.id} started successfully!`);
                        await loadInvestigations(); // Refresh from server
                    } else {
                        // For demo users, add to localStorage as before
                        investigation.investigator = formData.investigator;
                        investigation.type = formData.type;
                        investigation.priority = formData.priority;
                        
                        ensureInvestigationsArray();
                        investigations.push(investigation);
                        localStorage.setItem('osint_investigations', JSON.stringify(investigations));
                        
                        alert(`Investigation ${investigation.id} started successfully!`);
                        updateInvestigationDisplay();
                    }
                    
                    newForm.reset();
                } else {
                    const error = await response.json();
                    alert(`Failed to start investigation: ${error.detail}`);
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Error starting investigation: ' + error.message);
            }
        });
    }
});

console.log('Form fix script loaded');