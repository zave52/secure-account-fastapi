document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const response = form.querySelector('textarea[name="cf-turnstile-response"]');
            const target = form.querySelector('input[name="turnstile_token"]');
            if (response && target) target.value = response.value;
        });
    });
    document.querySelectorAll('input[type="password"]').forEach((input) => {
        const toggle = input.parentElement.querySelector(".password-toggle") ||
            document.createElement("button");
        if (!toggle.parentElement) {
            toggle.type = "button";
            toggle.className = "password-toggle";
            toggle.textContent = "Show";
            toggle.setAttribute("aria-label", "Show password");
            input.insertAdjacentElement("afterend", toggle);
        }
        toggle.addEventListener("click", () => {
            const isHidden = input.type === "password";
            input.type = isHidden ? "text" : "password";
            toggle.textContent = isHidden ? "Hide" : "Show";
            toggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
        });

        const meter = input.parentElement.querySelector(".password-length") ||
            document.createElement("small");
        if (!meter.parentElement) {
            meter.className = "password-length";
            toggle.insertAdjacentElement("afterend", meter);
        }
        input.addEventListener("input", () => {
            const length = input.value.length;
            meter.textContent = length ? `Password length: ${length}` : "";
            meter.className = length >= 8 ? "success" : "error";

            const strength = input.parentElement.querySelector(".password-strength");
            if (strength) {
                const checks = [
                    length >= 8,
                    /[A-Z]/.test(input.value),
                    /[a-z]/.test(input.value),
                    /\d/.test(input.value),
                    /[^A-Za-z0-9]/.test(input.value),
                ].filter(Boolean).length;
                const label = checks <= 2 ? "Weak" : checks <= 4 ? "Medium" : "Strong";
                strength.textContent = input.value ? `Strength: ${label}` : "";
                strength.className = `password-strength ${checks <= 2 ? "error" : checks <= 4 ? "warning" : "success"}`;
            }
        });
    });
});
