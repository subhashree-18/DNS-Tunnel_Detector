import React, { useEffect, useState } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Legend,
  Tooltip,
} from "chart.js";
import "./App.css";

ChartJS.register(LineElement, CategoryScale, LinearScale, PointElement, Legend, Tooltip);

function App() {
  const [data, setData] = useState([]);
  const [timestamps, setTimestamps] = useState([]);
  const [counts, setCounts] = useState([]);

  useEffect(() => {
    const evtSource = new EventSource("http://localhost:5000/api/live"); // change to your Render backend URL later

    evtSource.onmessage = (event) => {
      const newData = JSON.parse(event.data);
      setData(newData);

      const totalCount = newData.reduce((acc, item) => acc + item.count, 0);
      const now = new Date().toLocaleTimeString();
      setTimestamps((prev) => [...prev.slice(-19), now]);
      setCounts((prev) => [...prev.slice(-19), totalCount]);
    };

    evtSource.onerror = (err) => {
      console.error("SSE error:", err);
    };

    return () => evtSource.close();
  }, []);

  const chartData = {
    labels: timestamps,
    datasets: [
      {
        label: "Live Suspicious Query Activity",
        data: counts,
        fill: true,
        borderColor: "#58a6ff",
        backgroundColor: "rgba(88,166,255,0.2)",
        tension: 0.3,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: { labels: { color: "#c9d1d9" } },
    },
    scales: {
      x: {
        ticks: { color: "#c9d1d9" },
        grid: { color: "#30363d" },
      },
      y: {
        ticks: { color: "#c9d1d9" },
        grid: { color: "#30363d" },
      },
    },
  };

  return (
    <div className="App">
      <header className="header">
        <h1>🕵️‍♀️ DNS Tunnel Detector (Live)</h1>
        <p>Streaming suspicious DNS queries in real time</p>
      </header>

      <div className="chart-container">
        <Line data={chartData} options={options} />
      </div>

      <div className="table-container">
        <h2>🔍 Current Suspicious Domains</h2>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Query Count</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.length > 0 ? (
              data.map((entry, i) => (
                <tr key={i}>
                  <td>{entry.domain}</td>
                  <td>{entry.count}</td>
                  <td className={entry.count > 10 ? "suspicious" : "normal"}>
                    {entry.count > 10 ? "Suspicious" : "Normal"}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="3">No suspicious domains detected ✅</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;
