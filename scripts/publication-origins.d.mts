export interface PublicationOrigin {
  readonly namespace: string;
  readonly repository: string;
}
export const REPOSITORY_ID: string;
export const PUBLICATION_ORIGINS: readonly PublicationOrigin[];
export const CURRENT_PUBLICATION_ORIGIN: PublicationOrigin;
export const UPDATER_DOWNLOAD_REPOSITORY: string;
export function publicationOrigin(image: string, repository?: string): PublicationOrigin;
export function validateRepositoryId(record: unknown): void;
export function certificateOriginMatches(certificate: unknown, origin: PublicationOrigin): boolean;
export function provenanceOriginMatches(predicate: unknown, origin: PublicationOrigin): boolean;
export function publicationRunId(image: string, url: string): string | null;
export function validateImageSourceLabels(document: unknown, origin: PublicationOrigin): void;
export function publicationSourceOrigin(url: string): PublicationOrigin;
