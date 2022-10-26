export const toResultPageHref = (encryption, queryParams) =>
  `${PAGE_PATHS.RESULT}/${encryption}?${queryParams}`;
