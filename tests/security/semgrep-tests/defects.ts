// ruleid: frontend-consent-history-membership
const accepted = entry.acknowledgedModules.includes(module);
// ruleid: frontend-consent-history-membership
const current = older.acknowledgedModules.some(id => id === module);

// ok: frontend-consent-history-membership
const accepted = snapshot.currentConsentedModules.includes(module);



const tags = ['Questionnaires'];
// ruleid: test-array-self-membership
for (const tag of tags) { it(tag, () => { expect(tags).toContain(tag); }); }

// ok: test-array-self-membership
for (const status of statuses) { it(status, () => { expect(parseStatus(status)).toBe(status); }); }

