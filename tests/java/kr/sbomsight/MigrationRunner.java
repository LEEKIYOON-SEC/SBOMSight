package kr.sbomsight;

import org.flywaydb.core.api.configuration.Configuration;
import org.flywaydb.core.api.migration.Context;
import org.flywaydb.core.api.migration.JavaMigration;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;

/**
 * tests/check-migrations.sh 가 <b>자바 마이그레이션</b>(V25~)을 제 차례에 태울 때 부른다.
 *
 * <p>스크립트는 SQL 마이그레이션을 mysql 클라이언트로 태운다. 자바 마이그레이션은 Flyway 가 클래스로
 * 부르는 것이라 클라이언트로 태울 수 없다 — 여기서 같은 DB 에 붙어 그 클래스의 {@code migrate} 를
 * Flyway 처럼 한 트랜잭션으로 부른다. Flyway 가 그 클래스를 찾아 부르는 것은 tests/check-mariadb.sh
 * (Flyway 로 스키마를 만든다)와 띄운 앱이 본다.
 *
 * <p>이름이 {@code *Test} 가 아니라 평소의 {@code ./mvnw test} 에는 끼지 않는다(surefire 의 기본 포함
 * 규칙). 스크립트가 {@code -Dtest=MigrationRunner} 와 환경변수로 부른다 —
 * {@code MIGCHECK_URL} · {@code MIGCHECK_USER} · {@code MIGCHECK_PASSWORD} · {@code MIGCHECK_CLASS}.
 */
class MigrationRunner {

    @Test
    void migrate() throws Exception {
        String url = System.getenv("MIGCHECK_URL");
        Assumptions.assumeTrue(url != null, "tests/check-migrations.sh 가 부를 때만 돈다");
        JavaMigration migration = (JavaMigration) Class.forName(System.getenv("MIGCHECK_CLASS"))
                                                       .getDeclaredConstructor().newInstance();
        String password = System.getenv("MIGCHECK_PASSWORD");
        try (Connection connection = DriverManager.getConnection(
                url, System.getenv("MIGCHECK_USER"), password == null ? "" : password)) {
            connection.setAutoCommit(false);
            try {
                migration.migrate(new Context() {
                    @Override
                    public Configuration getConfiguration() {
                        return null;
                    }

                    @Override
                    public Connection getConnection() {
                        return connection;
                    }
                });
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            }
        }
    }
}
