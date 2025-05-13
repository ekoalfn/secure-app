import 'express-session';

// Type declarations for modules without types
declare module 'xss' {
  function filterXSS(html: string, options?: any): string;
  namespace filterXSS {
    function whiteList(): any;
  }
  export = filterXSS;
}

declare module 'class-sanitizer' {
  export function sanitize(object: any): void;
}

declare module 'class-transformer' {
  export function plainToClass(cls: any, plain: any, options?: any): any;
}

declare module 'class-validator' {
  export function validate(object: any, options?: any): Promise<ValidationError[]>;
  export class ValidationError {
    property: string;
    constraints: { [type: string]: string };
    children: ValidationError[];
  }
} 