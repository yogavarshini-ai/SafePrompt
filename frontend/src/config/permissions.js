// Single source of truth for what each role may do.
// The UI reads this to decide what to show, and the service layer
// (src/services/api.js) re-checks it on every call. The real backend
// must enforce the same table, because anything in the browser can be edited.

export const ROLE_LABELS = {
  admin: 'Administrator',
  hr: 'HR / Compliance',
  employee: 'Employee',
  manager: 'Manager',
  worker: 'Worker',
}

export const PERMISSIONS = {
  admin: {
    viewOwnHistory: true,
    viewTeamActivity: true,
    viewAllChats: true,
    viewAccounts: true,
    manageAccounts: true,
    viewAuditLog: true,
    flagPrompts: true,
    seeOriginalContent: true, // unmasked prompts, replies and values
    seeOthersAiReplies: true,
  },
  hr: {
    viewOwnHistory: true,
    viewTeamActivity: true,
    viewAllChats: false,
    viewAccounts: false,
    manageAccounts: false,
    viewAuditLog: false,
    flagPrompts: true,
    seeOriginalContent: true, // authorized to view restored vault entries
    seeOthersAiReplies: true,
  },
  employee: {
    viewOwnHistory: true,
    viewTeamActivity: false,
    viewAllChats: false,
    viewAccounts: false,
    manageAccounts: false,
    viewAuditLog: false,
    flagPrompts: false,
    seeOriginalContent: false,
    seeOthersAiReplies: false,
  },
  manager: {
    viewOwnHistory: true,
    viewTeamActivity: true, // workers, what they accessed, what they typed
    viewAllChats: false,
    viewAccounts: false,
    manageAccounts: false,
    viewAuditLog: false,
    flagPrompts: true, // the only "control" a manager has
    seeOriginalContent: false, // masked view only
    seeOthersAiReplies: false, // prompts only, no AI replies
  },
  worker: {
    viewOwnHistory: true,
    viewTeamActivity: false,
    viewAllChats: false,
    viewAccounts: false,
    manageAccounts: false,
    viewAuditLog: false,
    flagPrompts: false,
    seeOriginalContent: false,
    seeOthersAiReplies: false,
  },
}

export function can(role, permission) {
  return Boolean(PERMISSIONS[role]?.[permission])
}
