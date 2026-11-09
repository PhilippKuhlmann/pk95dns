// Runs in the page head before the first paint, otherwise the wrong theme would flash.
(function () {
  try {
    var theme = localStorage.getItem("pk95dns-theme");
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
  } catch (e) { /* Without storage the system setting applies. */ }
})();
