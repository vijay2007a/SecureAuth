export type WSEventType =
  | "simulation.initialized"
  | "simulation.started"
  | "simulation.progress"
  | "simulation.completed"
  | "simulation.failed"
  | "login_event"
  | "detection_result"
  | "alert_created"
  | "simulations.reset"
  | "ws_status";

export type WSEventListener = (payload: any) => void;

class WSEventTarget {
  private listeners: Map<string, Set<WSEventListener>> = new Map();

  on(type: WSEventType | string, listener: WSEventListener): () => void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set());
    }
    this.listeners.get(type)!.add(listener);

    return () => {
      this.off(type, listener);
    };
  }

  off(type: WSEventType | string, listener: WSEventListener): void {
    const set = this.listeners.get(type);
    if (set) {
      set.delete(listener);
      if (set.size === 0) {
        this.listeners.delete(type);
      }
    }
  }

  emit(type: WSEventType | string, payload: any): void {
    const set = this.listeners.get(type);
    if (set) {
      set.forEach((listener) => {
        try {
          listener(payload);
        } catch (err) {
          console.error(`Error in WS event listener for ${type}:`, err);
        }
      });
    }
  }
}

export const wsEvents = new WSEventTarget();
