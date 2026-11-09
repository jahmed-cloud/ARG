/**
 * Author and support links, in one place. Every author, sponsor and contact link in the
 * React app reads from here. README.md and .github/FUNDING.yml carry the same links.
 */
export const AUTHOR = {
  name: 'Junaid Ahmed',
  website: 'https://jahmed.cloud',
  websiteLabel: 'jahmed.cloud',
  github: 'https://github.com/jahmed-cloud',
  sponsor: 'https://github.com/sponsors/jahmed-cloud',
  email: 'iam@jahmed.cloud',
} as const;

export const PROJECT_LINKS = {
  repository: 'https://github.com/jahmed-cloud/ARG',
  dockerHub: 'https://hub.docker.com/repositories/jahmed22',
  roadmap: 'https://github.com/jahmed-cloud/ARG/blob/main/ROADMAP.md',
  contributing: 'https://github.com/jahmed-cloud/ARG/blob/main/CONTRIBUTING.md',
} as const;

// For every link that leaves ARG.
export const EXTERNAL_LINK = { target: '_blank', rel: 'noopener noreferrer' } as const;
