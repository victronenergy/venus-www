window.addEventListener("DOMContentLoaded", function() {
    checkBrowser();
}, false);

function checkBrowser() {
    const isChrome = navigator.userAgent.indexOf("Chrome") > -1;
    const isSafari = navigator.userAgent.indexOf("Safari") > -1 && !isChrome;
    const isIE = !!document.documentMode; // Check for Internet Explorer

    const heading = document.getElementById('browser_heading');
    const instructions = document.getElementById('browser_instructions');

    if (isChrome) {
        heading.textContent = 'On Chrome:';
        instructions.innerHTML = `
            <li>Click on ‘Show advanced options’</li>
            <li>Click on ‘Continue to website’</li>
        `;
    } else if (isSafari) {
        heading.textContent = 'On Safari:';
        instructions.innerHTML = `
            <li>Click on ‘Show details’</li>
            <li>Click on ‘Visit the website’</li>
        `;
    } else if (isIE) {
        heading.textContent = 'Internet Explorer:';
        instructions.innerHTML = `
            <li>Click on ‘Continue to this website (not recommended)’</li>
        `;
    }
}