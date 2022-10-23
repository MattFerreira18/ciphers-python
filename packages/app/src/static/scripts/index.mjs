import PAGE_PATHS from "./constants/pagePaths.js";

function main() {
  if (window.location.href === PAGE_PATHS.HOME) {
    // TODO attach form
    // TODO get values from input
    // TODO validate values of inputs
    // TODO show error messages, if necessary
    // TODO dynamic import helpers
    // TODO send to /encryption-results/{cryptograph} by query params
    // TODO request new page
    return;
  }

  if (window.location.href === PAGE_PATHS.RESULT) {
    return;
  }
}

main();
