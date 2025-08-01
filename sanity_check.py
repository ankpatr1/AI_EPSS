# epss_next30_with_plot.py

import pandas as pd
from prophet import Prophet
import matplotlib.pyplot as plt

# ─── 1. Manual change-point history ───────────────────────────────────────────
data = [
    ("2023-03-07",  8.60),
    ("2023-07-06",  9.02),
    ("2023-08-19",  9.66),
    ("2023-11-23",  7.82),
    ("2024-10-27",  7.22),
    ("2024-12-15",  6.87),
    ("2024-12-17", 56.40),
    ("2025-03-17", 49.12),
    ("2025-03-29", 55.51),
    ("2025-03-30", 49.12),
    ("2025-06-03", 57.32),
    ("2025-07-12", 74.31),
]
df = pd.DataFrame(data, columns=["Date", "EPSS_pct"])
df["Date"] = pd.to_datetime(df["Date"])
df = df.sort_values("Date")

# ─── 2. Prepare for Prophet ───────────────────────────────────────────────────
ts = df.rename(columns={"Date": "ds", "EPSS_pct": "y"})

# ─── 3. Fit the model ─────────────────────────────────────────────────────────
m = Prophet(
    daily_seasonality=False,
    weekly_seasonality=False,
    yearly_seasonality=False,
    interval_width=0.80   # 80% intervals
)
m.fit(ts)

# ─── 4. Forecast next 30 days ─────────────────────────────────────────────────
last_date = ts["ds"].max()
future   = m.make_future_dataframe(periods=30, freq="D")
forecast = m.predict(future)

# Slice out only the next 30 days
next30 = forecast[forecast["ds"] > last_date].head(30)[
    ["ds", "yhat", "yhat_lower", "yhat_upper"]
]
next30 = next30.rename(columns={
    "ds": "Date",
    "yhat": "Forecast",
    "yhat_lower": "Lower",
    "yhat_upper": "Upper"
})
next30[["Forecast","Lower","Upper"]] = next30[["Forecast","Lower","Upper"]].round(2)

# ─── 5. Print the numeric table ───────────────────────────────────────────────
print("\nNext 30-day EPSS Forecast (80% intervals):\n")
print(next30.to_string(index=False))

# ─── 6. Plot the results ─────────────────────────────────────────────────────
plt.figure(figsize=(10, 5))
plt.plot(ts["ds"], ts["y"], "ko", label="Historical change-points")
plt.plot(forecast["ds"], forecast["yhat"], lw=2, label="Forecast")
plt.fill_between(forecast["ds"],
                 forecast["yhat_lower"],
                 forecast["yhat_upper"],
                 color="blue", alpha=0.2,
                 label="80% uncertainty interval")
plt.axvline(last_date, color="gray", linestyle="--", label="Forecast start")
plt.xlim(last_date, future["ds"].max())
plt.xlabel("Date")
plt.ylabel("EPSS %")
plt.title("Next 30-Day EPSS % Forecast for CVE-2024-29943")
plt.legend()
plt.tight_layout()
plt.show()
