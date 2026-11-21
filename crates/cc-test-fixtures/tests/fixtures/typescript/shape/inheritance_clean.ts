// Sample clean cc.shape.no_inheritance: composition, not inheritance.

export interface Worker {
  readonly name: string;
}

export function workerAnnounce(worker: Worker): string {
  return `worker:${worker.name}`;
}

export interface Manager {
  readonly worker: Worker;
  readonly reports: readonly string[];
}

export function managerAnnounce(manager: Manager): string {
  return `manager:${manager.worker.name}:${manager.reports.length}`;
}
