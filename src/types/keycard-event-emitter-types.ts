export type Callback = (...args: any[]) => any;

export type Subscription = {
    unsubscribe: () => void
};