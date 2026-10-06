document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-demo-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const action = button.dataset.demoAction;
      const original = button.textContent;
      button.disabled = true;
      button.textContent = "Scanning…";
      try {
        const response = await fetch("/api/demo/mutate", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({action}),
        });
        const result = await response.json();
        if (!result.ok) throw new Error(result.error || "Demo action failed");
        window.location.reload();
      } catch (error) {
        button.disabled = false;
        button.textContent = original;
        window.alert(error.message);
      }
    });
  });

  document.querySelectorAll("[data-ack-alert]").forEach((button) => {
    button.addEventListener("click", async () => {
      await fetch(`/api/alerts/${button.dataset.ackAlert}/ack`, {method: "POST"});
      button.closest(".alert-card")?.remove();
    });
  });

  const chart = document.querySelector("[data-severity-chart]");
  if (chart) {
    chart.querySelectorAll("[data-value]").forEach((bar) => {
      const value = Number(bar.dataset.value || 0);
      const max = Number(chart.dataset.max || 1);
      bar.style.setProperty("--bar-height", `${Math.max(6, (value / Math.max(max, 1)) * 100)}%`);
    });
  }
});
