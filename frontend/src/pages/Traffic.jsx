import { useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useData } from '../context/DataContext.jsx';
import { Card, Empty, Page, Stat, chart } from '../components/ui.jsx';

export default function Traffic() {
  const { traffic, protocols } = useData();
  const [hours, setHours] = useState(24);

  const data = traffic.slice(-hours);
  const sum = (key) =>
    data.reduce((total, item) => total + Number(item[key] || 0), 0);

  const hasTraffic = traffic.length > 0;
  const hasProtocols = protocols.length > 0;

  return (
    <Page
      title="Traffic analytics"
      subtitle="Traffic analytics will appear when the backend provides traffic metrics."
      actions={
        hasTraffic ? (
          <div className="flex gap-2">
            {[6, 12, 24].map((hour) => (
              <button
                key={hour}
                className={`btn ${hour === hours ? 'btn-solid' : ''}`}
                onClick={() => setHours(hour)}
              >
                {hour}h
              </button>
            ))}
          </div>
        ) : null
      }
    >
      {!hasTraffic ? (
        <Card>
          <Empty
            title="Traffic analytics unavailable"
            hint="The current backend has no traffic time-series endpoint. No demo traffic is being shown as real data."
          />
        </Card>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Stat label="Inbound MB" value={sum('inbound')} />
            <Stat label="Outbound MB" value={sum('outbound')} />
            <Stat
              label="Peak inbound MB/h"
              value={Math.max(...data.map((item) => item.inbound))}
            />
          </div>

          <Card title="Volume (solid in, dashed out)">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={data}>
                <CartesianGrid {...chart.grid} />
                <XAxis dataKey="time" {...chart.axis} />
                <YAxis {...chart.axis} />
                <Tooltip {...chart.tooltip} />
                <Line
                  dataKey="inbound"
                  name="Inbound"
                  stroke="#fff"
                  dot={false}
                  strokeWidth={2}
                />
                <Line
                  dataKey="outbound"
                  name="Outbound"
                  stroke="#a1a1aa"
                  strokeDasharray="5 4"
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </>
      )}

      <Card title="Protocol share, % (24h)">
        {!hasProtocols ? (
          <Empty
            title="Protocol analytics unavailable"
            hint="The backend does not currently expose protocol-share statistics."
          />
        ) : (
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={protocols} layout="vertical">
              <XAxis type="number" {...chart.axis} />
              <YAxis
                type="category"
                dataKey="name"
                width={90}
                {...chart.axis}
              />
              <Tooltip {...chart.tooltip} />
              <Bar dataKey="value" name="Share %" fill="#e4e4e7" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </Card>
    </Page>
  );
}