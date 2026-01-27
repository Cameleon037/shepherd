(function() {
    const THEME_KEY = 'shepherd-theme';
    const DARK_THEME = 'dark';
    
    function getTheme() {
        return localStorage.getItem(THEME_KEY) || 'light';
    }
    
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem(THEME_KEY, theme);
        const toggleLink = document.querySelector('.theme-toggle-link');
        if (toggleLink) {
            toggleLink.innerHTML = '&nbsp;' + (theme === DARK_THEME ? 'Light mode' : 'Dark mode');
        }
    }
    
    function toggleTheme() {
        setTheme(getTheme() === DARK_THEME ? 'light' : DARK_THEME);
    }
    
    function addDarkModeMenuItem() {
        // Find the Preferences dropdown menu by looking for "Change Password" link
        const changePasswordLink = Array.from(document.querySelectorAll('.dropdown-menu a')).find(
            link => link.textContent.includes('Change Password')
        );
        
        if (changePasswordLink) {
            const dropdownMenu = changePasswordLink.closest('.dropdown-menu');
            if (dropdownMenu && !document.querySelector('.theme-toggle-link')) {
                const menuItem = document.createElement('li');
                const link = document.createElement('a');
                link.href = '#';
                link.className = 'theme-toggle-link';
                link.innerHTML = '&nbsp;Dark mode';
                link.onclick = function(e) {
                    e.preventDefault();
                    toggleTheme();
                    return false;
                };
                menuItem.appendChild(link);
                
                dropdownMenu.appendChild(menuItem);
            }
        }
    }
    
    // Initialize theme and add menu item when DOM is ready
    function init() {
        const currentTheme = getTheme();
        setTheme(currentTheme);
        addDarkModeMenuItem();
        // Update text after menu item is added
        setTheme(currentTheme);
    }
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // Expose toggle function globally
    window.toggleDarkMode = toggleTheme;
})();
