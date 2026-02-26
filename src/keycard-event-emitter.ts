import { Callback, Subscription } from "./types/keycard-event-emitter-types.ts";

class KeycardEventEmitter {
  map = new Map<string, Callback[]>();
  
  subscribe(eventName: string, callback: Callback): Subscription {
    if (!this.map.has(eventName)) {
      this.map.set(eventName, []);
    }
    
    const arr = this.map.get(eventName);

    if(arr) {
      arr.push(callback);
    }
    
    return { unsubscribe: () => arr!.splice(arr!.indexOf(callback), 1) };
  }
  
  emit(eventName: string, args: any = []): any[] {
    const handlers = this.map.get(eventName);
    
    if (handlers !== undefined && handlers !== null) {
      return handlers.map((handler) => handler(args));
    } else {
      return [];
    }
  }
}

export default KeycardEventEmitter;