/**
 * Tier 2: Benign Code Precision & Zero-False-Positive Benchmark Tests
 *
 * Verifies that standard benign coding tasks (e.g., sorting algorithms, Fibonacci scripts,
 * math utilities, prime checkers, normal file processing of non-secret workspace data)
 * pass with ALLOW (Risk Score < 50) and are never quarantined.
 *
 * Covers Features: F17
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ThreatHunter } = require('../src/threats/hunter');
const { WorkspaceInspector } = require('../src/watcher/inspector');

describe('Tier 2: Benign Code Precision Benchmark (Zero False Positives)', () => {
  const hunter = new ThreatHunter();

  describe('Algorithmic Benchmarks: Fibonacci & Recursion', () => {
    it('Allows iterative and recursive Python Fibonacci without false positives', () => {
      const pyFibonacci = `
def fibonacci_recursive(n):
    if n <= 0:
        return 0
    elif n == 1:
        return 1
    return fibonacci_recursive(n - 1) + fibonacci_recursive(n - 2)

def fibonacci_iterative(n):
    if n <= 0:
        return []
    sequence = [0, 1]
    while len(sequence) < n:
        sequence.append(sequence[-1] + sequence[-2])
    return sequence[:n]

if __name__ == '__main__':
    result = fibonacci_iterative(10)
    print(f"Fibonacci sequence: {result}")
`;
      const report = hunter.scan(pyFibonacci, 'algorithms/fibonacci.py');
      assert.strictEqual(report.verdict, 'ALLOW', `Fibonacci must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });

    it('Allows JavaScript memoized Fibonacci and dynamic programming table', () => {
      const jsFibonacci = `
function fibonacciMemo(n, memo = new Map()) {
  if (n <= 1) return n;
  if (memo.has(n)) return memo.get(n);
  const val = fibonacciMemo(n - 1, memo) + fibonacciMemo(n - 2, memo);
  memo.set(n, val);
  return val;
}

function fibonacciTable(n) {
  const table = new Array(n + 1).fill(0);
  table[1] = 1;
  for (let i = 2; i <= n; i++) {
    table[i] = table[i - 1] + table[i - 2];
  }
  return table[n];
}

console.log(fibonacciMemo(20));
console.log(fibonacciTable(20));
`;
      const report = hunter.scan(jsFibonacci, 'src/math/fibonacci.js');
      assert.strictEqual(report.verdict, 'ALLOW', `JS Fibonacci must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });
  });

  describe('Sorting Algorithms: QuickSort & MergeSort', () => {
    it('Allows Python QuickSort and MergeSort implementations', () => {
      const pySorts = `
def quicksort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)

def mergesort(arr):
    if len(arr) <= 1:
        return arr
    mid = len(arr) // 2
    left = mergesort(arr[:mid])
    right = mergesort(arr[mid:])
    return merge(left, right)

def merge(left, right):
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return result
`;
      const report = hunter.scan(pySorts, 'algorithms/sorting.py');
      assert.strictEqual(report.verdict, 'ALLOW', `Sorting algorithms must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });

    it('Allows JavaScript QuickSort and HeapSort implementations', () => {
      const jsSorts = `
function quickSort(arr, low = 0, high = arr.length - 1) {
  if (low < high) {
    const pIdx = partition(arr, low, high);
    quickSort(arr, low, pIdx - 1);
    quickSort(arr, pIdx + 1, high);
  }
  return arr;
}

function partition(arr, low, high) {
  const pivot = arr[high];
  let i = low - 1;
  for (let j = low; j < high; j++) {
    if (arr[j] < pivot) {
      i++;
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  }
  [arr[i + 1], arr[high]] = [arr[high], arr[i + 1]];
  return i + 1;
}

module.exports = { quickSort };
`;
      const report = hunter.scan(jsSorts, 'lib/sorters.js');
      assert.strictEqual(report.verdict, 'ALLOW', `JS QuickSort must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });
  });

  describe('Prime Checkers & Math Utilities', () => {
    it('Allows Python Sieve of Eratosthenes and Primality Checkers', () => {
      const pyPrimes = `
import math

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    for i in range(5, int(math.isqrt(num)) + 1, 6):
        if num % i == 0 or num % (i + 2) == 0:
            return False
    return True

def sieve_of_eratosthenes(limit):
    primes = [True] * (limit + 1)
    primes[0] = primes[1] = False
    for p in range(2, int(limit ** 0.5) + 1):
        if primes[p]:
            for i in range(p * p, limit + 1, p):
                primes[i] = False
    return [i for i, prime in enumerate(primes) if prime]
`;
      const report = hunter.scan(pyPrimes, 'math/primes.py');
      assert.strictEqual(report.verdict, 'ALLOW', `Prime checker must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });

    it('Allows complex mathematical expressions and matrix calculations in Python and JS', () => {
      const pyMatrixMath = `
import math

def solve_quadratic(a, b, c):
    discriminant = b ** 2 - 4 * a * c
    if discriminant < 0:
        return None
    root1 = (-b + math.sqrt(discriminant)) / (2 * a)
    root2 = (-b - math.sqrt(discriminant)) / (2 * a)
    return (root1, root2)

def matrix_multiply(A, B):
    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])
    if cols_A != rows_B:
        raise ValueError("Incompatible dimensions")
    C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
    for i in range(rows_A):
        for j in range(cols_B):
            for k in range(cols_A):
                C[i][j] += A[i][k] * B[k][j]
    return C
`;
      const report = hunter.scan(pyMatrixMath, 'math/matrix_solver.py');
      assert.strictEqual(report.verdict, 'ALLOW', `Matrix calculations must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });
  });

  describe('Standard Workspace File Processing (Non-Secret Data)', () => {
    it('Allows reading and aggregating benign JSON workspace files in Python', () => {
      const pyJsonAggregator = `
import json
from pathlib import Path

def process_metrics(input_path, output_path):
    p = Path(input_path)
    if not p.exists():
        return
    with open(p, 'r', encoding='utf-8') as f:
        data = json.load(f)
    scores = [item.get('score', 0) for item in data.get('records', [])]
    mean_val = sum(scores) / len(scores) if scores else 0.0
    summary = {
        'count': len(scores),
        'mean': mean_val
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

if __name__ == '__main__':
    process_metrics('data/samples.json', 'data/summary.json')
`;
      const report = hunter.scan(pyJsonAggregator, 'pipelines/aggregate.py');
      assert.strictEqual(report.verdict, 'ALLOW', `Standard file I/O must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });

    it('Allows reading and transforming CSV files in Node.js', () => {
      const jsCsvProcessor = `
const fs = require('fs');
const path = require('path');

function parseCsv(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.trim().split('\\n');
  const headers = lines[0].split(',');
  const rows = lines.slice(1).map(line => {
    const vals = line.split(',');
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h.trim()] = vals[idx]?.trim();
    });
    return obj;
  });
  return rows;
}

module.exports = { parseCsv };
`;
      const report = hunter.scan(jsCsvProcessor, 'src/data/csvParser.js');
      assert.strictEqual(report.verdict, 'ALLOW', `CSV processor must be ALLOWED, got ${report.verdict}`);
      assert.ok(report.riskScore < 50, `Risk score must be < 50, got ${report.riskScore}`);
    });
  });

  describe('Quarantine Prevention for Benign Code', () => {
    let testWorkspace;

    it('Ensures benign files are never quarantined by WorkspaceInspector', async () => {
      testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'benign_workspace_'));
      const qDir = path.join(testWorkspace, '.firewall-quarantine');

      const inspector = new WorkspaceInspector({
        cwd: testWorkspace,
        config: {
          quarantineBlocked: true,
          quarantineDir: '.firewall-quarantine',
          blockOnRiskScore: 80,
        },
      });

      const benignFilePath = path.join(testWorkspace, 'calculator.py');
      const benignCode = `
# Benign Calculator
def compute_area(radius):
    import math
    return math.pi * (radius ** 2)

print(compute_area(5))
`;
      fs.writeFileSync(benignFilePath, benignCode, 'utf8');

      // Inspect file
      await inspector.inspectFile(benignFilePath);

      // Verify file remains intact
      const diskContent = fs.readFileSync(benignFilePath, 'utf8');
      assert.strictEqual(diskContent, benignCode, 'Benign file content must not be modified or quarantined');
      assert.strictEqual(
        diskContent.includes('[AI AGENT FIREWALL] - FILE QUARANTINED'),
        false,
        'File must not contain quarantine placeholder'
      );

      // Verify quarantine folder does not contain any quarantined copy
      if (fs.existsSync(qDir)) {
        const qFiles = fs.readdirSync(qDir).filter((f) => f.includes('calculator'));
        assert.strictEqual(qFiles.length, 0, 'No quarantine backup should exist for benign file');
      }

      // Cleanup
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    });
  });
});
