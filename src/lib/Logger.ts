class Logger {
    private static instance: Logger;
    private silent: boolean;
    private originalConsoleLog: (...args: any[]) => void;

    private constructor(silent: boolean = false) {
        this.silent = silent;
        this.originalConsoleLog = console.log;
        console.log = (...args: any[]) => {
            if (!this.silent) {
                this.originalConsoleLog(...args);
            }
        };
    }

    public static getInstance(silent?: boolean): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger(silent ?? false);
        }
        return Logger.instance;
    }

    public setSilentMode(silent: boolean): void {
        this.silent = silent;
    }

    public log(message: string, ...optionalParams: any[]): void {
        console.log(message, ...optionalParams);
    }
}

export default Logger;
