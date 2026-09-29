// Shared submit logic for every OpenOSINT Cloud waitlist form on the site
// (the homepage's compact form and the full /cloud/waitlist/ page). Posts
// directly to Formspree — see CLOUD.md §12 for why this isn't the gateway's
// own POST /v1/waitlist endpoint right now.
//
// Markup contract: a <form data-waitlist-form data-form-location="...">
// containing elements tagged with data-wl-email, data-wl-consent,
// data-wl-gotcha, data-wl-submit, data-wl-status, and optionally
// data-wl-role / data-wl-use-case (the full page has these; the homepage's
// compact form doesn't, and that's fine — missing fields are sent as null).
(function () {
  var FORMSPREE_ENDPOINT = "https://formspree.io/f/mkjgkvyj";

  function setStatus(statusEl, message, state) {
    if (!statusEl) return;
    statusEl.textContent = message;
    statusEl.setAttribute("data-state", state || "");
  }

  function extractErrorMessage(data) {
    if (data && Array.isArray(data.errors) && data.errors.length) {
      return data.errors
        .map(function (e) { return e.message || e.field; })
        .filter(Boolean)
        .join(" ");
    }
    if (data && typeof data.error === "string") {
      return data.error;
    }
    return "Something went wrong. Try again.";
  }

  function initWaitlistForm(form) {
    var submitBtn = form.querySelector("[data-wl-submit]");
    var statusEl = form.querySelector("[data-wl-status]");
    var emailEl = form.querySelector("[data-wl-email]");
    var consentEl = form.querySelector("[data-wl-consent]");
    var gotchaEl = form.querySelector("[data-wl-gotcha]");
    var roleEl = form.querySelector("[data-wl-role]");
    var useCaseEl = form.querySelector("[data-wl-use-case]");
    var formLocation = form.getAttribute("data-form-location") || "waitlist_page";

    // Pass utm_source / ref from the URL into the source field, no tracking script involved.
    var params = new URLSearchParams(window.location.search);
    var source = params.get("utm_source") || params.get("ref") || "";

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var email = emailEl ? emailEl.value.trim() : "";
      var consent = consentEl ? consentEl.checked : false;
      if (!email) {
        setStatus(statusEl, "Enter your email address.", "err");
        return;
      }
      if (!consent) {
        setStatus(statusEl, "Please check the consent box to join.", "err");
        return;
      }

      var planEl = form.querySelector('input[name="plan_interest"]:checked');
      var payload = {
        email: email,
        role: roleEl ? (roleEl.value || null) : null,
        use_case: useCaseEl ? (useCaseEl.value.trim() || null) : null,
        plan_interest: (planEl && planEl.value) || null,
        consent: consent,
        source: source || null,
        form_location: formLocation,
        _gotcha: gotchaEl ? gotchaEl.value : "",
      };

      if (submitBtn) submitBtn.disabled = true;
      setStatus(statusEl, "Joining…", "");

      fetch(FORMSPREE_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(payload),
      })
        .then(function (resp) {
          return resp.json().then(function (data) {
            return { ok: resp.ok, data: data };
          });
        })
        .then(function (result) {
          if (result.ok) {
            setStatus(statusEl, "You're on the list. We'll email you when OpenOSINT Cloud opens up.", "ok");
            form.reset();
          } else {
            setStatus(statusEl, extractErrorMessage(result.data), "err");
          }
        })
        .catch(function () {
          setStatus(statusEl, "Network error. Try again in a moment.", "err");
        })
        .finally(function () {
          if (submitBtn) submitBtn.disabled = false;
        });
    });
  }

  function init() {
    var forms = document.querySelectorAll("[data-waitlist-form]");
    for (var i = 0; i < forms.length; i++) {
      initWaitlistForm(forms[i]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
