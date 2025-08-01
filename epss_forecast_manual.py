# epss_forecast_to_dec.py
# pip install pandas prophet matplotlib

import pandas as pd
from prophet import Prophet
import matplotlib.pyplot as plt

# 1. Your manual EPSS history (Date, New EPSS %)
data = [
    ("2024-05-02",  0.05),
    ("2024-06-28",  0.05),
    ("2025-03-17", 24.60),
    ("2025-03-20",  5.25),
    ("2025-03-23", 24.60),
    ("2025-03-27", 34.45),
    ("2025-03-28", 24.60),
    ("2025-04-02", 23.94),
    ("2025-04-15", 17.04),
    ("2025-04-30", 42.07),
    ("2025-05-09", 59.08),
    ("2025-05-15", 63.21),
    ("2025-06-01", 46.77),
    ("2025-06-04", 63.21),
    ("2025-07-01", 46.77),
    ("2025-07-04", 63.21),
]

# 2. Build & sort DataFrame
df = pd.DataFrame(data, columns=["Date", "EPSS_pct"])
df["Date"] = pd.to_datetime(df["Date"])
df = df.sort_values("Date")

# 3. Rename columns for Prophet
ts = df.rename(columns={"Date": "ds", "EPSS_pct": "y"})

# 4. Fit Prophet model
m = Prophet(daily_seasonality=False, yearly_seasonality=False)
m.add_seasonality(name="weekly", period=7, fourier_order=3)
m.fit(ts)

# 5. Compute how many days until Dec 31, 2025
last_date = ts["ds"].max()
end_date  = pd.to_datetime("2025-12-31")
periods   = (end_date - last_date).days

# 6. Create future DataFrame through 2025-12-31
future = m.make_future_dataframe(periods=periods, freq="D")

# 7. Predict
forecast = m.predict(future)

# 8. Plot the full timeline
fig = m.plot(forecast)
plt.title("EPSS % Forecast for CVE-2024-29943 Through 2025-12-31")
plt.xlabel("Date")
plt.ylabel("EPSS Percentage")
plt.tight_layout()
plt.show()

# 9. (Optional) Inspect the tail of the forecast
print(forecast[forecast["ds"] >= "2025-12-01"][["ds", "yhat", "yhat_lower", "yhat_upper"]])
