// Cleanup script to fix old investigations with missing or incorrect timestamps
// Run this in the browser console

console.log('Starting cleanup of old investigations...');

// Get current investigations
let investigations = JSON.parse(localStorage.getItem('osint_investigations') || '[]');
console.log(`Found ${investigations.length} investigations`);

// Fix timestamps and remove very old investigations
const now = Date.now();
let fixed = 0;
let removed = 0;

investigations = investigations.filter(inv => {
    // Check if created_at is missing or invalid
    if (!inv.created_at) {
        console.log(`Investigation ${inv.target} has no created_at timestamp - removing`);
        removed++;
        return false;
    }
    
    // Convert created_at to proper format if needed
    let createdAt = inv.created_at;
    if (typeof createdAt === 'string') {
        createdAt = new Date(createdAt).getTime() / 1000;
    } else if (createdAt > 1000000000000) {
        // If timestamp is in milliseconds, convert to seconds
        createdAt = createdAt / 1000;
    }
    
    // Calculate age
    const ageInHours = (now - (createdAt * 1000)) / (1000 * 60 * 60);
    
    // Remove investigations older than 24 hours
    if (ageInHours > 24) {
        console.log(`Removing ${inv.target} - ${ageInHours.toFixed(1)} hours old`);
        removed++;
        return false;
    }
    
    // Fix the timestamp format
    if (inv.created_at !== createdAt) {
        inv.created_at = createdAt;
        fixed++;
    }
    
    // Remove any report data from old investigations (> 1 hour)
    if (ageInHours > 1 && inv.report_generated) {
        console.log(`Removing expired report from ${inv.target}`);
        inv.report_generated = false;
        delete inv.report_generated_at;
        fixed++;
    }
    
    return true;
});

console.log(`Fixed ${fixed} investigations`);
console.log(`Removed ${removed} old investigations`);
console.log(`${investigations.length} investigations remaining`);

// Save cleaned data
localStorage.setItem('osint_investigations', JSON.stringify(investigations));

// Force reload the display
if (typeof updateInvestigationDisplay === 'function') {
    updateInvestigationDisplay();
} else {
    location.reload();
}

console.log('Cleanup complete!');