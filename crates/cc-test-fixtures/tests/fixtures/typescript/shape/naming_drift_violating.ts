// Sample violating cc.shape.naming_drift: camelCase crowd, one snake_case.

export function fetchUser(userId: number): object {
  return { id: userId };
}

export function updateUser(userId: number, payload: object): object {
  return { id: userId, ...payload };
}

// snake_case outlier — drift.
export function delete_user(userId: number): boolean {
  return userId > 0;
}

export function listUsers(): object[] {
  return [];
}
