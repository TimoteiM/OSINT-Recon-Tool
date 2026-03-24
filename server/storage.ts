// Simple passthrough storage — OSINT app is stateless (no DB needed)
export interface IStorage {}

export class MemStorage implements IStorage {}
export const storage = new MemStorage();
