import pandas as pd
from prophet import Prophet
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ─── 1. Historical data CVE-2011-3166 EPSS score history───────────────────────────────────────────────────────
history = [
    ("2025-07-14", 21.34, 42.82,  21.48),
    ("2025-07-04", 26.52, 21.34,  -5.18),
    ("2025-03-30", 32.23, 26.52,  -5.71),
    ("2025-03-29", 26.52, 32.23,   5.71),
    ("2025-03-25", 25.33, 26.52,   1.19),
    ("2025-03-17", 43.21, 25.33, -17.88),
    ("2024-12-17", 65.19, 43.21, -21.98),
    ("2024-09-30", 58.22, 65.19,   6.97),
    ("2024-01-15", 47.94, 58.22,  10.28),
    ("2023-11-21", 47.13, 47.94,   0.81),
    ("2023-03-07", 25.14, 47.13,  21.99),
]
df = pd.DataFrame(history, columns=["Date","Old","New","Delta"])
df["Date"] = pd.to_datetime(df["Date"])
df = df.sort_values("Date")

# print history
print("\nEPSS Change-Point History:")
print(
    df.assign(
        Old=lambda x: x["Old"].map("{:.2f}%".format),
        New=lambda x: x["New"].map("{:.2f}%".format),
        Delta=lambda x: x["Delta"].map("{:+.2f}%".format),
    )
    .to_string(index=False)
)

# ─── 2. forecast 60 days ────────────────────────────────────────
ts = df[["Date","New"]].rename(columns={"Date":"ds","New":"y"})
m = Prophet(daily_seasonality=False, weekly_seasonality=False,
            yearly_seasonality=False, interval_width=0.80)
m.fit(ts)

future   = m.make_future_dataframe(periods=60, freq="D")
forecast = m.predict(future)

# isolate 60-day forecast
last_obs = ts.ds.max()
fc = forecast[forecast.ds > last_obs].copy().head(60)
fc["yhat"]       = fc["yhat"].round(2)
fc["lower"]      = fc["yhat_lower"].round(2)
fc["upper"]      = fc["yhat_upper"].round(2)
fc["height"]     = fc["upper"] - fc["lower"]

# print forecast
print("\nNext 60-Day EPSS score :")
print(
    fc[["ds","yhat","lower","upper"]]
    .rename(columns={"ds":"Date","yhat":"EPSS score","lower":"Lower","upper":"Upper"})
    .to_string(index=False, formatters={
        "Forecast": "{:.2f}%".format,
        "Lower": "{:.2f}%".format,
        "Upper": "{:.2f}%".format
    })
)

# ─── 3. Plot interactive with bar‐bands ───────────────────────────────────────
fig = make_subplots(specs=[[{"secondary_y": True}]])

# a) Historical EPSS line & markers
fig.add_trace(
    go.Scatter(
        x=df.Date, y=df.New,
        mode="lines+markers",
        name="Historical EPSS",
        line=dict(color="firebrick", width=2),
        marker=dict(color="firebrick", size=8),
        hovertemplate="Date: %{x|%Y-%m-%d}<br>EPSS: %{y:.2f}%<br>Δ: %{customdata:+.2f}%<extra></extra>",
        customdata=df.Delta
    ),
    secondary_y=False
)

# b) Historical Delta bars
fig.add_trace(
    go.Bar(
        x=df.Date, y=df.Delta,
        name="Delta",
        marker_color=df.Delta.apply(lambda d: "purple" if d>0 else "green"),
        opacity=0.6,
        hovertemplate="Date: %{x|%Y-%m-%d}<br>Δ: %{y:+.2f}%<extra></extra>"
    ),
    secondary_y=True
)

# c) Forecast bar‐bands for the CI
bar_width = (fc.ds.iloc[1] - fc.ds.iloc[0]).days * 0.4  # 40% of daily step
fig.add_trace(
    go.Bar(
        x=fc.ds, base=fc["lower"], y=fc["height"],
        name="80% CI",
        marker_color="rgba(65,105,225,0.2)",
        width=bar_width,
        hovertemplate="Date: %{x|%Y-%m-%d}<br>Lower: %{base:.2f}%<br>Upper: %{y+base:.2f}%<extra></extra>"
    ),
    secondary_y=False
)

# d) Forecast line
fig.add_trace(
    go.Scatter(
        x=fc.ds, y=fc.yhat,
        mode="lines+markers",
        name="60-Day Forecast",
        line=dict(color="royalblue", dash="dash"),
        marker=dict(color="royalblue", size=6),
        hovertemplate=(
            "Date: %{x|%Y-%m-%d}<br>"
            "Forecast: %{y:.2f}%<br>"
            "Lower: %{customdata[0]:.2f}%<br>"
            "Upper: %{customdata[1]:.2f}%<extra></extra>"
        ),
        customdata=fc[["lower","upper"]].values
    ),
    secondary_y=False
)

# ─── 4. Axes & layout ─────────────────────────────────────────────────────────
fig.update_yaxes(title_text="EPSS (%)", secondary_y=False, tickformat=".0f%")
fig.update_yaxes(title_text="Delta (%)", secondary_y=True,  tickformat="+.0f%")
fig.update_xaxes(title_text="Date", tickangle=-45,
                 range=[df.Date.min(), fc.ds.max()])

fig.update_layout(
    title="EPSS History & next 60-Day  (Bar-Bands)",
    hovermode="x unified",
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    margin=dict(l=50, r=50, t=100, b=100),
    template="plotly_white",
    width=900, height=500
)

fig.show()
