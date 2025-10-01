import React, { useEffect, useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchSuspicious = async () => {
      try {
        const res = await axios.get('http://localhost:5000/api/suspicious');
        setData(res.data);
      } catch (err) {
        console.error("Error fetching suspicious domains", err);
      }
    };

    const interval = setInterval(fetchSuspicious, 5000); // auto-refresh every 5s
    fetchSuspicious();

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="App">
      <h1>⚠️ Suspicious DNS Queries</h1>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Query Count</th>
          </tr>
        </thead>
        <tbody>
          {data.map((entry, i) => (
            <tr key={i}>
              <td>{entry.domain}</td>
              <td>{entry.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
