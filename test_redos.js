// ReDoS vulnerability demonstration
function testRegexVulnerability() {
    // Simulating the vulnerable code from wysihtml5
    const nodeTypes = Array(1000).fill('a').concat(['b']); // Create large input
    console.time('regex-test');
    try {
        // The vulnerable pattern construction
        const regex = new RegExp("^(" + nodeTypes.join("|") + ")$");
        // Test with a specially crafted input that causes catastrophic backtracking
        const testString = 'a'.repeat(25) + 'b!'; // String that won't match but takes long to process
        regex.test(testString);
    } catch (e) {
        console.error('Error:', e);
    }
    console.timeEnd('regex-test');
}

console.log('Starting ReDoS test...');
testRegexVulnerability();
console.log('Test completed.');