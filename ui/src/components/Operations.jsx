import CollectionHealth from './CollectionHealth'
import RuleUsage from './RuleUsage'
import RetentionPolicy from './RetentionPolicy'

export default function Operations() {
  return <div className="h-full overflow-y-auto space-y-8 p-4 max-w-screen-2xl mx-auto text-gray-200">
    <CollectionHealth />
    <div className="border-t border-gray-800 pt-6"><RuleUsage /></div>
    <div className="border-t border-gray-800 pt-6"><RetentionPolicy /></div>
  </div>
}
