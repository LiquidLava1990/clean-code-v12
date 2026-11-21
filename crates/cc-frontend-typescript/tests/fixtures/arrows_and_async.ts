export const inc = (x: number): number => x + 1;

export const fetchUser = async (id: string): Promise<string> => {
    const result = await Promise.resolve(id);
    return result;
};
