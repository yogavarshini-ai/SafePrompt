import { can } from './permissions'

// `perm: null` means every signed-in user may open the page.
export const ROUTES = [
  { path: 'chat', label: 'New chat', perm: null },
  { path: 'history', label: 'My history', perm: 'viewOwnHistory' },
  { path: 'team', label: 'Team activity', perm: 'viewTeamActivity' },
  { path: 'all-chats', label: 'All chats', perm: 'viewAllChats' },
  { path: 'accounts', label: 'Accounts', perm: 'viewAccounts' },
  { path: 'audit', label: 'Audit log', perm: 'viewAuditLog' },
]

export function routesFor(role) {
  return ROUTES.filter((route) => !route.perm || can(role, route.perm))
}
