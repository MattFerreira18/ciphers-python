export const toQueryParams = (obj) =>
  Object.entries(obj).reduce(
    (prev, [key, value]) =>
      prev.length === 0 ? `${key}=${value}` : `${prev}&${key}=${value}`,
    ""
  );

export const toResultPageHref = (encryption, queryParams) =>
  `${PAGE_PATHS.RESULT}/${encryption}?${queryParams}`;
