// Nest adapter, kept out of the root entry so services without Nest never load @nestjs/*.
// Import it as `lrv-commons/dist/nest`.
export * from './authorization/adapters/nest';
