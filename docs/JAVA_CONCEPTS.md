# Comprehensive Java & Spring Boot Architecture Guide (JAVA_CONCEPTS.md)

This document provides a deep, code-grounded analysis of the enterprise Java and Spring Boot architecture employed in the **Adaptive Cyberattack Detection & Prevention System (Mini-SOC)**. Every concept described herein is cross-referenced with exact production classes and methods from the project.

---

## Table of Contents
1. [Core Object-Oriented Programming (OOP) Principles](#1-core-object-oriented-programming-oop-principles)
   - [Encapsulation & Domain Modeling](#encapsulation--domain-modeling)
   - [Abstraction via Service Contracts](#abstraction-via-service-contracts)
   - [Polymorphism & Strategy Dispatch](#polymorphism--strategy-dispatch)
   - [Type-Safe Enums](#type-safe-enums)
2. [Spring Core & Dependency Injection (IoC)](#2-spring-core--dependency-injection-ioc)
   - [Inversion of Control & Component Stereotypes](#inversion-of-control--component-stereotypes)
   - [Constructor-Based Dependency Injection](#constructor-based-dependency-injection)
   - [Dynamic Property Configuration via `@Value`](#dynamic-property-configuration-via-value)
3. [Spring Data JPA & Entity Relationship Management](#3-spring-data-jpa--entity-relationship-management)
   - [Entity Lifecycle & UUID Identity Mapping](#entity-lifecycle--uuid-identity-mapping)
   - [Bidirectional Relationships & JSON Recursion Control](#bidirectional-relationships--json-recursion-control)
   - [Cascade Strategy & Detached Entity Safety](#cascade-strategy--detached-entity-safety)
   - [Derived Query Methods & Projections](#derived-query-methods--projections)
4. [Asynchronous Execution & Concurrency](#4-asynchronous-execution--concurrency)
   - [Non-Blocking Background Tasks via `@Async`](#non-blocking-background-tasks-via-async)
   - [Task Completion & Future Handling with `CompletableFuture`](#task-completion--future-handling-with-completablefuture)
5. [Transaction Management (`@Transactional`)](#5-transaction-management-transactional)
   - [ACID Guarantees & Read-Only Optimizations](#acid-guarantees--read-only-optimizations)
   - [Controlled Multi-Entity State Transitions](#controlled-multi-entity-state-transitions)
6. [Resilience & Robust Error Handling](#6-resilience--robust-error-handling)
   - [Custom Domain Exceptions](#custom-domain-exceptions)
   - [Centralized Exception Handling with `@RestControllerAdvice`](#centralized-exception-handling-with-restcontrolleradvice)
7. [Enterprise RESTful Web Services & DTO Pattern](#7-enterprise-restful-web-services--dto-pattern)
   - [Request Validation via Jakarta Constraints](#request-validation-via-jakarta-constraints)
   - [Clean Separation between DTOs and Persistence Entities](#clean-separation-between-dtos-and-persistence-entities)

---

## 1. Core Object-Oriented Programming (OOP) Principles

### Encapsulation & Domain Modeling
Encapsulation prevents direct state tampering by making entity state fields `private` and exposing controlled accessors (`getters`) and mutators (`setters`), coupled with declarative Jakarta Bean Validation.

**Example from `com.cyberattack.soc.model.ThreatAlert`:**
```java
@Entity
@Table(name = "threat_alerts")
public class ThreatAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private DataSource dataSource;

    @Column(nullable = false)
    private Double riskScore;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RiskLevel riskLevel;

    @Column(nullable = false, length = 60)
    private String attackType;

    // Encapsulated accessors and mutators
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) {
        if (riskScore < 0.0 || riskScore > 100.0) {
            throw new IllegalArgumentException("Risk score must reside between 0.0 and 100.0");
        }
        this.riskScore = riskScore;
    }
}
```

### Abstraction via Service Contracts
The application strictly decouples business capabilities from their concrete execution through Java interfaces. Consumers interact exclusively with the abstract contract.

**Interface Definition (`com.cyberattack.soc.service.AdaptiveThresholdService`):**
```java
public interface AdaptiveThresholdService {
    List<AdaptiveThreshold> getAllThresholds();
    AdaptiveThreshold getThreshold(String metricName);
    AdaptiveThreshold updateThreshold(String metricName, Double newThreshold, String reason);
    boolean processFeedbackAdjustment(String alertIdStr, String feedbackTypeStr, String reason);
    Map<String, Object> getBaselineStatus();
}
```

**Concrete Implementation (`com.cyberattack.soc.service.impl.AdaptiveThresholdServiceImpl`):**
```java
@Service
@Transactional
public class AdaptiveThresholdServiceImpl implements AdaptiveThresholdService {
    // Encapsulated algorithmic logic, threshold clamping, and audit logging
}
```

### Polymorphism & Strategy Dispatch
The mitigation engine dynamically generates actionable containment scripts based on the runtime `ActionType` without rigid conditional chains.

**Example from `com.cyberattack.soc.service.impl.MitigationServiceImpl`:**
```java
private String generateContainmentScript(ActionType actionType, String targetIp) {
    return switch (actionType) {
        case BLOCK_IP -> String.format(
            "sudo iptables -A INPUT -s %s -j DROP\n" +
            "sudo iptables -A OUTPUT -d %s -j DROP\n" +
            "logger -p auth.crit \"[SOC-CONTAINMENT] IP %s blocked via iptables\"",
            targetIp, targetIp, targetIp
        );
        case RATE_LIMIT -> String.format(
            "sudo iptables -A INPUT -p tcp -s %s -m limit --limit 50/minute -j ACCEPT\n" +
            "sudo iptables -A INPUT -p tcp -s %s -j DROP",
            targetIp, targetIp
        );
        case ISOLATE_HOST -> String.format(
            "sudo ip link set dev eth0 down\n" +
            "logger -p auth.emerg \"[SOC-ISOLATION] Host %s interface disconnected\"",
            targetIp
        );
        default -> "# Action: " + actionType + " logged for manual operator review.";
    };
}
```

### Type-Safe Enums
Enums eliminate brittle string literals, preventing typo-induced logic errors and guaranteeing clean database mapping via `@Enumerated(EnumType.STRING)`.

```java
public enum DataSource {
    OBSERVED,
    SIMULATED,
    DATASET
}

public enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

public enum AlertStatus {
    NEW,
    INVESTIGATING,
    RESOLVED,
    FALSE_POSITIVE,
    CONFIRMED_THREAT
}
```

---

## 2. Spring Core & Dependency Injection (IoC)

### Inversion of Control & Component Stereotypes
Spring's IoC container manages component instantiation, lifecycle, and wiring via specialized stereotype annotations:
- `@RestController`: Exposes REST HTTP endpoints with JSON serialization.
- `@Service`: Contains transactional domain business logic.
- `@Repository`: Manages data access and translates database exceptions.
- `@Configuration`: Configures cross-cutting infrastructure beans (CORS, RestTemplate).

### Constructor-Based Dependency Injection
The codebase enforces modern constructor-based dependency injection. This guarantees:
1. Immutability via `final` fields.
2. Complete initialization at construction time.
3. Ease of mocking in unit and integration tests without Spring reflection proxies.

**Example from `com.cyberattack.soc.controller.AlertController`:**
```java
@RestController
@RequestMapping("/api/v1/alerts")
public class AlertController {

    private final ThreatAlertRepository alertRepository;
    private final MitigationService mitigationService;
    private final AdaptiveThresholdService thresholdService;

    // Explicit constructor injection
    public AlertController(ThreatAlertRepository alertRepository,
                           MitigationService mitigationService,
                           AdaptiveThresholdService thresholdService) {
        this.alertRepository = alertRepository;
        this.mitigationService = mitigationService;
        this.thresholdService = thresholdService;
    }
}
```

### Dynamic Property Configuration via `@Value`
Externalized configuration allows identical compiled artifacts to operate seamlessly across Local Development (H2 in-memory), CI/CD, and Cloud Production (Render/Netlify).

**Example from `com.cyberattack.soc.config.CorsConfig`:**
```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${soc.cors.allowed-origins:http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000,https://*.netlify.app}")
    private String allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String[] origins = Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);

        registry.addMapping("/**")
                .allowedOriginPatterns(origins)
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
```

---

## 3. Spring Data JPA & Entity Relationship Management

### Entity Lifecycle & UUID Identity Mapping
All primary entities leverage universally unique identifiers (`UUID`), preventing enumeration vulnerabilities and enabling client-side or distributed ID pre-generation without collision risks.

```java
@Id
@GeneratedValue(strategy = GenerationType.UUID)
private UUID id;
```

### Bidirectional Relationships & JSON Recursion Control
Bidirectional navigation between parent (`Incident`) and child (`ThreatAlert`) is maintained while eliminating infinite cyclic serialization loops using Jackson annotations.

**Parent (`com.cyberattack.soc.model.Incident`):**
```java
@OneToMany(mappedBy = "incident", cascade = {CascadeType.MERGE, CascadeType.REFRESH}, fetch = FetchType.LAZY)
@JsonManagedReference
private List<ThreatAlert> alerts = new ArrayList<>();
```

**Child (`com.cyberattack.soc.model.ThreatAlert`):**
```java
@ManyToOne(fetch = FetchType.LAZY)
@JoinColumn(name = "incident_id")
@JsonBackReference
private Incident incident;
```

### Cascade Strategy & Detached Entity Safety
A classic JPA pitfall is `CascadeType.PERSIST` on a collection containing pre-existing, detached entities, which throws `InvalidDataAccessApiUsageException: detached entity passed to persist`. In our system, `Incident` uses:
```java
cascade = {CascadeType.MERGE, CascadeType.REFRESH}
```
This safely links already-persisted `ThreatAlert` records into newly formed incidents without illegal duplicate persistence triggers.

### Derived Query Methods & Projections
Spring Data automatically parses repository method signatures into optimized SQL queries at runtime without requiring raw JPQL strings.

**Example from `com.cyberattack.soc.repository.ThreatAlertRepository`:**
```java
@Repository
public interface ThreatAlertRepository extends JpaRepository<ThreatAlert, UUID> {
    List<ThreatAlert> findByStatusOrderByTimestampDesc(AlertStatus status);
    List<ThreatAlert> findByDataSourceOrderByTimestampDesc(DataSource dataSource);
    List<ThreatAlert> findByStatusAndDataSourceOrderByTimestampDesc(AlertStatus status, DataSource dataSource);
    long countByStatus(AlertStatus status);
}
```

---

## 4. Asynchronous Execution & Concurrency

### Non-Blocking Background Tasks via `@Async`
Network attack simulations generate dozens to hundreds of synthetic events across several seconds. Executing this synchronously on the HTTP request thread would exhaust web server worker threads and trigger HTTP 504 gateway timeouts.

**Enabling Concurrency (`com.cyberattack.soc.CyberattackSocApplication`):**
```java
@SpringBootApplication
@EnableAsync
public class CyberattackSocApplication { ... }
```

**Asynchronous Execution (`com.cyberattack.soc.service.impl.SimulationServiceImpl`):**
```java
@Override
@Async
public CompletableFuture<Void> runSimulationAsync(String runId, SimulationScenario scenario,
                                                  String targetIp, Integer targetPort, Double durationSeconds) {
    SimulationRun run = runRepository.findById(runId).orElse(null);
    try {
        int packetsToInject = (int) Math.max(10, durationSeconds * 15);
        int alertsCount = 0;

        for (int i = 0; i < packetsToInject; i++) {
            NetworkEvent event = generateSyntheticEvent(scenario, targetIp, targetPort, runId);
            eventRepository.save(event);

            DetectionResultDTO result = detectionService.processEvent(event);
            if (result.isAlertGenerated()) {
                alertsCount++;
            }
            Thread.sleep(50);
        }

        run.setStatus("COMPLETED");
        run.setEndedAt(LocalDateTime.now());
        run.setTotalPacketsInjected(packetsToInject);
        run.setDetectedAlertsCount(alertsCount);
        runRepository.save(run);
    } catch (Exception ex) {
        run.setStatus("FAILED");
        run.setErrorMessage(ex.getMessage());
        run.setEndedAt(LocalDateTime.now());
        runRepository.save(run);
    }
    return CompletableFuture.completedFuture(null);
}
```

---

## 5. Transaction Management (`@Transactional`)

### ACID Guarantees & Read-Only Optimizations
The `@Transactional` annotation guarantees that operations either commit completely or roll back in the event of an unhandled runtime exception.
- `@Transactional(readOnly = true)`: Instructs Hibernate to disable snapshot generation and dirty-checking, minimizing memory overhead for read-heavy operations.
- `@Transactional`: Guarantees atomicity when persisting mitigation actions, updating alert statuses, and adjusting adaptive thresholds simultaneously.

**Example from `com.cyberattack.soc.service.impl.DetectionServiceImpl`:**
```java
@Override
@Transactional
public DetectionResultDTO processEvent(NetworkEvent event) {
    // 1. Ensure event is persisted
    NetworkEvent savedEvent = eventRepository.save(event);

    // 2. Query ML Inference Microservice
    MLPredictionResponseDTO mlResponse = callPythonMlEngine(savedEvent);

    // 3. Evaluate Rule-Based Threat Signatures
    RuleEvaluationResult ruleResult = evaluateHeuristicRules(savedEvent);

    // 4. Synthesize Hybrid Risk Score
    double hybridScore = calculateHybridScore(mlResponse, ruleResult);

    // 5. Conditionally persist alert and initial mitigation
    if (hybridScore >= 60.0) {
        ThreatAlert alert = createAlert(savedEvent, hybridScore, mlResponse, ruleResult);
        alertRepository.save(alert);
        mitigationService.recommendAction(alert);
    }
    return new DetectionResultDTO(...);
}
```

---

## 6. Resilience & Robust Error Handling

### Custom Domain Exceptions
Domain-specific exceptions decouple HTTP semantics from service logic, clarifying operational failures.

```java
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) { super(message); }
}

public class MLServiceUnavailableException extends RuntimeException {
    public MLServiceUnavailableException(String message, Throwable cause) { super(message, cause); }
}
```

### Centralized Exception Handling with `@RestControllerAdvice`
Uncaught exceptions are intercepted globally and translated into clean, predictable JSON error contracts adhering to RFC 7807 problem details.

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
            "timestamp", Instant.now().toString(),
            "status", 404,
            "error", "Resource Not Found",
            "message", ex.getMessage()
        ));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(e -> errors.put(e.getField(), e.getDefaultMessage()));
        return ResponseEntity.badRequest().body(Map.of(
            "timestamp", Instant.now().toString(),
            "status", 400,
            "error", "Validation Failed",
            "validation_errors", errors
        ));
    }
}
```

---

## 7. Enterprise RESTful Web Services & DTO Pattern

### Request Validation via Jakarta Constraints
Input payloads are rigorously verified at the controller boundary before hitting service layers.

**Example from `com.cyberattack.soc.dto.MitigationRequestDTO`:**
```java
public class MitigationRequestDTO {

    @NotNull(message = "Action type is required")
    private ActionType actionType = ActionType.BLOCK_IP;

    @NotBlank(message = "Target IP address cannot be blank")
    private String targetIp;

    private String analystNotes;

    // Getters and Setters
}
```

### Complete Separation: DTOs vs Entities
- **Entities** represent database tables and internal relationships.
- **DTOs** (Data Transfer Objects) represent the public API contract, hiding sensitive internal structures, preventing over-posting vulnerabilities, and decoupling database schema migrations from client frontend versions.
