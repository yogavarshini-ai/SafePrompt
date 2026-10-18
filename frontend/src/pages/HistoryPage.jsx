import PageHeader from '../components/PageHeader'
import ChatRecord from '../components/ChatRecord'
import { EmptyState, ErrorMessage, Loading } from '../components/StateMessage'
import { useLoad } from '../hooks/useLoad'
import { getMyHistory } from '../services/api'
import { can } from '../config/permissions'

export default function HistoryPage({ user }) {
  const { data, error, loading } = useLoad(() => getMyHistory(user))
  const unmasked = can(user.role, 'seeOriginalContent')

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="My history"
        description={
          unmasked
            ? 'Every prompt you have sent, with the original text and restored replies.'
            : 'Your own prompts, exactly as they were sent to the AI. Masked values appear as dark bars.'
        }
      />
      {loading ? <Loading /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {data && data.length === 0 ? (
        <EmptyState title="No prompts yet" hint="Send a prompt from New chat and it will appear here." />
      ) : null}
      <div className="space-y-4">
        {data ? data.map((record) => <ChatRecord key={record.id} record={record} />) : null}
      </div>
    </div>
  )
}
