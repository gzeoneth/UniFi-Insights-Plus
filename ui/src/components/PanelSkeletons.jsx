// Keep loading placeholders independent of chart and map dependencies.

export function DashboardSkeleton() {
  return (
    <div className="p-4 space-y-4 overflow-auto max-h-full animate-pulse">
      {/* Time range selector */}
      <div className="flex gap-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-7 w-10 bg-gray-800 rounded" />
        ))}
      </div>
      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="h-2.5 w-24 bg-gray-800 rounded" />
          <div className="h-7 w-16 bg-gray-800 rounded" />
          <div className="flex gap-2">
            {[...Array(3)].map((_, i) => <div key={i} className="h-6 w-20 bg-gray-800 rounded" />)}
          </div>
          <div className="flex gap-2 pt-3 border-t border-gray-800/50">
            {[...Array(4)].map((_, i) => <div key={i} className="h-6 w-24 bg-gray-800 rounded" />)}
          </div>
        </div>
        <div className="border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="h-2.5 w-16 bg-gray-800 rounded" />
          <div className="flex flex-wrap gap-2">
            {[...Array(4)].map((_, i) => <div key={i} className="h-6 w-24 bg-gray-800 rounded" />)}
          </div>
        </div>
      </div>
      {/* Charts */}
      <div className="border border-gray-800 rounded-lg p-4 h-40" />
      <div className="border border-gray-800 rounded-lg p-4 h-52" />
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Allowed panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
    </div>
  )
}

export function ThreatMapSkeleton() {
  return (
    <div className="h-full flex flex-col animate-pulse">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800">
        <div className="h-7 w-10 bg-gray-800 rounded" />
        <div className="h-7 w-10 bg-gray-800 rounded" />
        <div className="h-7 w-10 bg-gray-800 rounded" />
      </div>
      <div className="flex-1 bg-black" />
    </div>
  )
}
