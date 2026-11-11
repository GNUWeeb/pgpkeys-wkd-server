// matcha.js: the copy buttons. Every page works without it. A button with
// data-copy shows only once this script finds the Clipboard API (a secure
// context), and the text it copies is on the page for everyone else.
"use strict";

if (navigator.clipboard) {
	document.documentElement.classList.add("can-copy");
	document.addEventListener("click", (event) => {
		const button = event.target.closest("[data-copy]");
		if (!button) {
			return;
		}
		button.dataset.label ??= button.textContent;
		navigator.clipboard.writeText(button.dataset.copy).then(
			() => { button.textContent = "Copied"; },
			() => { button.textContent = "Copy failed"; },
		).finally(() => {
			setTimeout(() => { button.textContent = button.dataset.label; }, 2000);
		});
	});
}
