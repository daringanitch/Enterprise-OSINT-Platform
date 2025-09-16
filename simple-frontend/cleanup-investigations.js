/*
 * Copyright (c) 2025 Darin Ganitch
 *
 * This file is part of the Enterprise OSINT Platform.
 * Licensed under the Enterprise OSINT Platform License.
 * Individual use is free. Commercial use requires 3% profit sharing.
 * See LICENSE file for details.
 */

// Comprehensive cleanup script for investigation data
// Run this in the browser console to fix all 85 investigations

console.log('=== Starting comprehensive investigation cleanup ===');

// Get current investigations
let investigations = JSON.parse(localStorage.getItem('osint_investigations') || '[]');
console.log(`Found ${investigations.length} investigations`);

// Analysis
let noTimestamp = 0;
let invalidTimestamp = 0;
let tooOld = 0;
let duplicates = 0;
let fixed = 0;

// Track unique investigations
const uniqueTargets = new Map();

// Filter and fix investigations
const cleanedInvestigations = [];

investigations.forEach((inv, index) => {
    // Check for missing target
    if (!inv.target) {
        console.log(`Investigation ${index} has no target - removing`);
        return;
    }
    
    // Check for duplicates
    const key = `${inv.target}-${inv.investigation_type || inv.type || 'unknown'}`;
    if (uniqueTargets.has(key)) {
        console.log(`Duplicate found: ${inv.target} - removing`);
        duplicates++;
        return;
    }
    uniqueTargets.set(key, true);
    
    // Check timestamp
    if (!inv.created_at) {
        console.log(`${inv.target} has no timestamp - removing`);
        noTimestamp++;
        return;
    }
    
    // Fix timestamp format
    let timestamp = inv.created_at;
    if (typeof timestamp === 'string') {
        timestamp = new Date(timestamp).getTime();
        if (isNaN(timestamp)) {
            console.log(`${inv.target} has invalid timestamp: ${inv.created_at} - removing`);
            invalidTimestamp++;
            return;
        }
        // Convert to seconds if needed
        if (timestamp > 1000000000000) {
            timestamp = timestamp / 1000;
        }
        inv.created_at = timestamp;
        fixed++;
    } else if (timestamp > 1000000000000) {
        // Timestamp in milliseconds, convert to seconds
        inv.created_at = timestamp / 1000;
        fixed++;
    }
    
    // Calculate age
    const ageHours = (Date.now() - (inv.created_at * 1000)) / (1000 * 60 * 60);
    
    // Remove if older than 24 hours
    if (ageHours > 24) {
        console.log(`${inv.target} is ${ageHours.toFixed(1)} hours old - removing`);
        tooOld++;
        return;
    }
    
    // Ensure required fields
    inv.status = inv.status || 'processing';
    inv.priority = inv.priority || 'normal';
    inv.investigator = inv.investigator || 'System';
    inv.type = inv.type || inv.investigation_type || 'comprehensive';
    
    // Reset report data for investigations older than 1 hour
    if (ageHours > 1 && inv.report_generated) {
        console.log(`${inv.target} is ${ageHours.toFixed(1)} hours old - clearing report data`);
        inv.report_generated = false;
        delete inv.report_generated_at;
    }
    
    cleanedInvestigations.push(inv);
});

// Summary
console.log('\n=== Cleanup Summary ===');
console.log(`Original investigations: ${investigations.length}`);
console.log(`No timestamp: ${noTimestamp}`);
console.log(`Invalid timestamp: ${invalidTimestamp}`);
console.log(`Too old (>24h): ${tooOld}`);
console.log(`Duplicates: ${duplicates}`);
console.log(`Fixed timestamps: ${fixed}`);
console.log(`Remaining investigations: ${cleanedInvestigations.length}`);

// Save cleaned data
localStorage.setItem('osint_investigations', JSON.stringify(cleanedInvestigations));

// Clear demo flag to allow fresh demo data
localStorage.removeItem('demo_data_loaded');

console.log('\n✅ Cleanup complete! Refreshing page...');
location.reload();