// script.js

// Function to parse and format VirusTotal URL scan results
function parseVirusTotalURLResults(data) {
    // Check if the response indicates an error or incomplete analysis
    if (data.error) {
        return `
URL Analysis Report
--------------------
Status: Error
Message: ${data.error}
        `;
    }

    const attributes = data.data.attributes;
    const status = attributes.status;

    // If the analysis is not complete, show a message
    if (status !== 'completed') {
        return `
URL Analysis Report
--------------------
Status: ${status}
Message: Analysis is not yet complete. Please try again later.
        `;
    }

    const lastAnalysisResults = attributes.results || {}; // Note: Use 'results' instead of 'last_analysis_results'

    // Count detection categories
    const detectionCategories = Object.values(lastAnalysisResults).reduce((acc, result) => {
        acc[result.category] = (acc[result.category] || 0) + 1;
        return acc;
    }, {});

    // Find malicious detections
    const maliciousDetections = Object.entries(lastAnalysisResults)
        .filter(([_, result]) => result.category === 'malicious')
        .map(([engine, result]) => `${engine}: ${result.result}`);

    // Extract categories (if available)
    const categories = Object.entries(lastAnalysisResults)
        .filter(([_, result]) => result.category === 'undetected' && result.result)
        .map(([engine, result]) => `${engine}: ${result.result}`);

    // Prepare formatted results
    let formattedResults = `
URL Analysis Report
--------------------
Detection Summary:
- Total Engines: ${Object.keys(lastAnalysisResults).length}
- Undetected: ${detectionCategories['undetected'] || 0}
- Malicious: ${detectionCategories['malicious'] || 0}
- Suspicious: ${detectionCategories['suspicious'] || 0}
- Type Unsupported: ${detectionCategories['type-unsupported'] || 0}

Malicious Detections:
${maliciousDetections.length > 0 
    ? maliciousDetections.join('\n') 
    : 'No engines detected the URL as malicious'}

Categories:
${categories.length > 0 
    ? categories.join('\n') 
    : 'No specific categories identified'}

Last Analyzed: ${new Date(attributes.date * 1000).toUTCString()}

Risk Assessment: ${maliciousDetections.length > 0 
    ? 'HIGH - Potential Threat Detected' 
    : 'LOW - No Significant Threats'}
    `;

    return formattedResults;
}

// Function to perform AbuseIPDB scan
async function abuseIPDBScan() {
    const input = document.getElementById('ipInput').value;
    const resultsDiv = document.getElementById('ipResults');
    
    try {
        const response = await fetch('/abuseipdb', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ input: input })
        });

        const data = await response.json();
        const formattedResults = `
ISP: ${data.data.isp}

Usage Type: ${data.data.usageType}

ASN: ${data.data.ipVersion === 4 ? 'AS' + data.data.asnumber : 'N/A'}

Hostname(s): ${data.data.hostnames?.join(', ') || 'N/A'}

Domain Name: ${data.data.domain || 'N/A'}

Country: ${getFullCountryName(data.data.countryCode)}

Abuse Confidence Score: ${data.data.abuseConfidenceScore}%

Total Reports: ${data.data.totalReports}

Last Reported: ${new Date(data.data.lastReportedAt).toUTCString()}
        `;

        resultsDiv.innerHTML = `
            <h3>AbuseIPDB Results</h3>
            <pre>${formattedResults}</pre>
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">${error.message}</div>`;
    }
}

// Helper function to get full country name
function getFullCountryName(countryCode) {
    const countryNames = {
        'US': 'United States of America',
        // Add more country codes as needed
    };
    return countryNames[countryCode] || countryCode;
}

// Function to perform VirusTotal IP scan
async function virusTotalIPScan() {
    const input = document.getElementById('ipInput').value;
    const resultsDiv = document.getElementById('ipResults');
    
    try {
        const response = await fetch('/virustotal', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ input: input })
        });

        const data = await response.json();
        const attributes = data.data.attributes;

        const formattedResults = `
Basic Properties

Network: ${attributes.network || 'N/A'}

Autonomous System Number: ${attributes.asn || 'N/A'}

Autonomous System Label: ${attributes.as_owner || 'N/A'}

Regional Internet Registry: ${attributes.regional_internet_registry || 'N/A'}

Country: ${attributes.country || 'N/A'}

Continent: ${attributes.continent || 'N/A'}
        `;

        resultsDiv.innerHTML = `
            <h3>VirusTotal IP Results</h3>
            <pre>${formattedResults}</pre>
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">${error.message}</div>`;
    }
}

// Function to perform VirusTotal URL scan
async function virusTotalURLScan() {
    const input = document.getElementById('urlInput').value;
    const resultsDiv = document.getElementById('urlResults');
    
    try {
        const response = await fetch('/virustotal', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ input: input })
        });

        const data = await response.json();
        console.log("Raw VirusTotal Response:", data); // Keep this for debugging

        resultsDiv.innerHTML = `
            <h3>VirusTotal URL Results</h3>
            <pre>${parseVirusTotalURLResults(data)}</pre>
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">${error.message}</div>`;
    }
}