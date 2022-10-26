import PAGE_PATHS from "./constants/pagePaths.js";

function main() {
  if (window.location.pathname === PAGE_PATHS.HOME) {
    const input = document.querySelector('input[name="plaintext"]');

    input.addEventListener('keyup', () => {
      input.value = input.value.toUpperCase();
    });

    return;
  }

  if (window.location.pathname === PAGE_PATHS.RESULT) {
    const encryptions = document.querySelectorAll('span[role="button"]')

    encryptions.forEach(encryption => encryption.addEventListener('click', () => {
      navigator.clipboard.writeText(encryption.innerText).then(() => {
        alert('Criptografia copiada na área de transferễncia com sucesso!!!')
      });
    }))

    return;
  }
}

main();
